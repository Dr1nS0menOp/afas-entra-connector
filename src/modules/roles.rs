// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Roles: membership of Entra groups follows AFAS attributes. Licences follow
//! through group-based licensing on those groups.
//!
//! Safety: only groups named in the rules are touched; each must start with
//! `group_prefix`, be a cloud group, not role-assignable and not dynamic. Members
//! that are not linked to an employee in this upload are left alone unless
//! `remove_unknown_members` is set. More changes than `max_changes_per_run` → nothing.

use super::records::{AccessEntry, Exception, ExceptionKind, append_access, load_exceptions, now};
use super::settings::{RoleRule, RolesConfig};
use super::{Action, Ctx, Found, ModuleReport, Person, match_users, with_graph};
use crate::graph::{EntraUser, GResult, Graph, USER_SELECT, seg};
use chrono::NaiveDate;
use reqwest::Method;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub members: Vec<EntraUser>,
}

/// Refuses groups the tool must never manage.
pub fn check_group(v: &Value, prefix: &str) -> Result<String, String> {
    let id = v["id"].as_str().unwrap_or("?");
    let name = v["displayName"].as_str().unwrap_or("").to_string();
    if !name.starts_with(prefix) {
        return Err(format!(
            "group {id} ('{name}') does not start with group_prefix '{prefix}'"
        ));
    }
    if v["isAssignableToRole"].as_bool() == Some(true) {
        return Err(format!("group '{name}' is role-assignable; refused"));
    }
    if v["onPremisesSyncEnabled"].as_bool() == Some(true) {
        return Err(format!(
            "group '{name}' is synchronised from on-premises AD; it cannot be changed in Entra"
        ));
    }
    if v["groupTypes"]
        .as_array()
        .is_some_and(|t| t.iter().any(|x| x == "DynamicMembership"))
    {
        return Err(format!("group '{name}' has dynamic membership; refused"));
    }
    Ok(name)
}

fn value_of<'a>(p: &'a Person, key: &str) -> Option<&'a str> {
    let s = &p.snap;
    match key {
        "department" => s.department.as_deref(),
        "job_title" => s.job_title.as_deref(),
        "job_profile" => s.job_profile.as_deref(),
        "office" => s.office.as_deref(),
        "company" => s.company.as_deref(),
        "employee_type" => s.employee_type.as_deref(),
        "cost_center" => s.cost_center.as_deref(),
        "population" => p.population.as_deref(),
        _ => None,
    }
}

pub fn rule_matches(rule: &RoleRule, p: &Person) -> bool {
    if rule.all {
        return true;
    }
    rule.criteria().iter().all(|(key, wanted)| {
        wanted.is_empty()
            || value_of(p, key).is_some_and(|v| {
                wanted
                    .iter()
                    .any(|w| w.trim().eq_ignore_ascii_case(v.trim()))
            })
    })
}

/// Should this person have groups at all today?
pub fn eligible(cfg: &RolesConfig, p: &Person, today: NaiveDate) -> bool {
    let s = &p.snap;
    if s.active {
        return true;
    }
    if s.start_date > today {
        return cfg.include_prehires;
    }
    // Leaver.
    s.end_date.is_some_and(|end| {
        end.checked_add_days(chrono::Days::new(u64::from(cfg.keep_leavers_days)))
            .is_some_and(|until| until >= today)
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolesPlan {
    /// (group, user, employee id)
    pub adds: Vec<(String, EntraUser, Option<String>)>,
    pub removes: Vec<(String, EntraUser, Option<String>)>,
    pub notes: Vec<String>,
}

pub fn plan(
    cfg: &RolesConfig,
    people: &[Person],
    found: &HashMap<String, Found>,
    groups: &[GroupInfo],
    exceptions: &[Exception],
    today: NaiveDate,
) -> RolesPlan {
    let lc = |s: &str| s.to_ascii_lowercase();
    let managed: BTreeSet<String> = groups.iter().map(|g| lc(&g.id)).collect();
    let mut out = RolesPlan::default();
    // user id -> (employee id, desired groups)
    let mut desired: HashMap<String, (String, BTreeSet<String>)> = HashMap::new();
    let current: HashMap<String, BTreeSet<String>> = {
        let mut m: HashMap<String, BTreeSet<String>> = HashMap::new();
        for g in groups {
            for u in &g.members {
                m.entry(u.id.clone()).or_default().insert(lc(&g.id));
            }
        }
        m
    };
    for x in exceptions {
        if x.until >= today && !managed.contains(&lc(&x.group_id)) {
            out.notes.push(format!(
                "exception {} for {} ignored: group {} is not in the role rules",
                x.id, x.employee_id, x.group_id
            ));
        }
    }
    for p in people {
        let mut want: BTreeSet<String> = if eligible(cfg, p, today) {
            cfg.rules
                .iter()
                .filter(|r| rule_matches(r, p))
                .map(|r| lc(&r.group_id))
                .collect()
        } else {
            BTreeSet::new()
        };
        for x in exceptions
            .iter()
            .filter(|x| x.employee_id == p.employee_id && x.until >= today)
        {
            let g = lc(&x.group_id);
            if !managed.contains(&g) {
                continue;
            }
            match x.kind {
                ExceptionKind::Include => want.insert(g),
                ExceptionKind::Exclude => want.remove(&g),
            };
        }
        match found.get(&p.employee_id) {
            Some(Found::User(u)) => {
                let have = current.get(&u.id).cloned().unwrap_or_default();
                for s in &cfg.sod {
                    let set: BTreeSet<String> = s.groups.iter().map(|g| lc(g)).collect();
                    let hits = want.intersection(&set).count();
                    if hits >= 2 {
                        out.notes.push(format!(
                            "conflicting groups (segregation of duties) '{}': {} would be in {} of its groups; their membership of these groups is left unchanged",
                            s.name, p.employee_id, hits
                        ));
                        for g in &set {
                            if have.contains(g) {
                                want.insert(g.clone());
                            } else {
                                want.remove(g);
                            }
                        }
                    } else if have.intersection(&set).count() >= 2 {
                        out.notes.push(format!(
                            "conflicting groups (segregation of duties) '{}': {} is already in {} of its groups (outside the rules)",
                            s.name,
                            p.employee_id,
                            have.intersection(&set).count()
                        ));
                    }
                }
                desired.insert(u.id.clone(), (p.employee_id.clone(), want));
            }
            Some(Found::Conflict(why)) => {
                out.notes
                    .push(format!("{}: not changed, {why}", p.employee_id));
            }
            Some(Found::Missing) | None => {
                if !want.is_empty() {
                    out.notes.push(format!(
                        "{}: not in Entra yet; groups follow once the account is synchronised",
                        p.employee_id
                    ));
                }
            }
        }
    }
    let users: HashMap<&str, &EntraUser> = match_index(found);
    for g in groups {
        let gid = lc(&g.id);
        let members: BTreeSet<&str> = g.members.iter().map(|u| u.id.as_str()).collect();
        let mut adds: BTreeMap<String, (EntraUser, String)> = BTreeMap::new();
        for (uid, (emp, want)) in &desired {
            if want.contains(&gid)
                && !members.contains(uid.as_str())
                && let Some(u) = users.get(uid.as_str())
            {
                adds.insert(uid.clone(), ((*u).clone(), emp.clone()));
            }
        }
        for (_, (u, emp)) in adds {
            out.adds.push((g.id.clone(), u, Some(emp)));
        }
        let mut removes: Vec<&EntraUser> = g.members.iter().collect();
        removes.sort_by(|a, b| a.id.cmp(&b.id));
        for m in removes {
            match desired.get(&m.id) {
                Some((emp, want)) => {
                    if !want.contains(&gid) {
                        out.removes
                            .push((g.id.clone(), m.clone(), Some(emp.clone())));
                    }
                }
                None => {
                    if cfg.remove_unknown_members {
                        out.removes
                            .push((g.id.clone(), m.clone(), m.employee_id.clone()));
                    }
                }
            }
        }
    }
    out.notes.sort();
    out.notes.dedup();
    out
}

fn match_index(found: &HashMap<String, Found>) -> HashMap<&str, &EntraUser> {
    found
        .values()
        .filter_map(|f| match f {
            Found::User(u) => Some((u.id.as_str(), u)),
            _ => None,
        })
        .collect()
}

fn read_groups(g: &Graph<'_>, cfg: &RolesConfig) -> Result<Vec<GroupInfo>, String> {
    let mut ids: Vec<String> = cfg
        .rules
        .iter()
        .map(|r| r.group_id.to_ascii_lowercase())
        .collect();
    ids.sort();
    ids.dedup();
    let mut out = Vec::new();
    for id in ids {
        let id = seg(&id).map_err(|e| e.to_string())?;
        let v = g
            .get(&format!(
                "groups/{id}?$select=id,displayName,isAssignableToRole,onPremisesSyncEnabled,groupTypes"
            ))
            .map_err(|e| format!("group {id}: {e}"))?;
        let name = check_group(&v, &cfg.group_prefix)?;
        let members = g
            .get_all(&format!(
                "groups/{id}/members/microsoft.graph.user?$select={USER_SELECT}&$top=999"
            ))
            .map_err(|e| format!("members of '{name}': {e}"))?
            .iter()
            .filter_map(EntraUser::from_json)
            .collect();
        out.push(GroupInfo {
            id: id.to_string(),
            name,
            members,
        });
    }
    Ok(out)
}

fn add_member(g: &Graph<'_>, base: &str, group: &str, user: &str) -> GResult<()> {
    let body = json!({ "@odata.id": format!("{}/directoryObjects/{}", base.trim_end_matches('/'), seg(user)?) });
    match g.call(
        Method::POST,
        &format!("groups/{}/members/$ref", seg(group)?),
        Some(&body),
    ) {
        Ok(_) => Ok(()),
        // Already a member: the goal is reached.
        Err(e)
            if e.status == Some(400)
                && e.message.to_ascii_lowercase().contains("already exist") =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn remove_member(g: &Graph<'_>, group: &str, user: &str) -> GResult<()> {
    match g.call(
        Method::DELETE,
        &format!("groups/{}/members/{}/$ref", seg(group)?, seg(user)?),
        None,
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.status == Some(404) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn run(ctx: &Ctx<'_>, cfg: &RolesConfig) -> ModuleReport {
    let exceptions = match load_exceptions(ctx.state_dir) {
        Ok(x) => x.items,
        Err(e) => return ModuleReport::errored(e),
    };
    let res = with_graph(ctx, &cfg.identity(), |g| -> Result<ModuleReport, String> {
        let users = ctx.users(g).map_err(|e| format!("users: {e}"))?;
        let found = match_users(ctx.people, &users);
        let groups = read_groups(g, cfg)?;
        let p = plan(cfg, ctx.people, &found, &groups, &exceptions, ctx.today);
        let names: HashMap<String, String> = groups
            .iter()
            .map(|g| (g.id.clone(), g.name.clone()))
            .collect();
        let mut rep = ModuleReport {
            notes: p.notes.clone(),
            ..Default::default()
        };
        let act = |kind: &str, (gid, u, emp): &(String, EntraUser, Option<String>)| Action {
            action: kind.into(),
            employee_id: emp.clone(),
            upn: Some(u.upn.clone()),
            target: Some(names.get(gid).cloned().unwrap_or_else(|| gid.clone())),
            detail: None,
        };
        rep.planned = p
            .adds
            .iter()
            .map(|a| act("add_to_group", a))
            .chain(p.removes.iter().map(|r| act("remove_from_group", r)))
            .collect();
        let total = rep.planned.len();
        if total > cfg.max_changes_per_run as usize {
            rep.violations.push(format!(
                "{total} group changes planned, maximum is {}; nothing changed (check the rules, or raise roles.max_changes_per_run deliberately)",
                cfg.max_changes_per_run
            ));
        } else if ctx.apply {
            let base = ctx.cfg.entra.graph_base.as_str();
            for (kind, item) in p
                .adds
                .iter()
                .map(|a| ("add_to_group", a))
                .chain(p.removes.iter().map(|r| ("remove_from_group", r)))
            {
                let (gid, u, emp) = item;
                let res = if kind == "add_to_group" {
                    add_member(g, base, gid, &u.id)
                } else {
                    remove_member(g, gid, &u.id)
                };
                let a = act(kind, item);
                let logged = append_access(
                    ctx.state_dir,
                    &AccessEntry {
                        utc: now(),
                        module: "roles".into(),
                        action: kind.into(),
                        employee_id: emp.clone(),
                        upn: a.upn.clone(),
                        target: a.target.clone(),
                        ok: res.is_ok(),
                        detail: res.as_ref().err().map(ToString::to_string),
                        actor: ctx.actor.into(),
                    },
                );
                super::note_log_failure(&mut rep, logged);
                match res {
                    Ok(()) => rep.applied += 1,
                    Err(e) => rep.failed.push(format!(
                        "{kind} {} {}: {e}",
                        a.upn.unwrap_or_default(),
                        a.target.unwrap_or_default()
                    )),
                }
            }
        }
        rep.graph_calls = g.calls.get();
        Ok(rep)
    });
    match res {
        Ok(Ok(r)) => r,
        Ok(Err(e)) | Err(e) => ModuleReport::errored(e),
    }
}
