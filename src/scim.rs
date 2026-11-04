// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! SCIM bulk payloads as described in the Microsoft Graph `bulkUpload` documentation.

use crate::plan::PlannedRecord;
use serde_json::{Map, Value, json};

pub const BULK_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub const CORE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// Custom extension for attributes without a standard SCIM field. Requires a schema extension
/// in the provisioning app (see README, "Extra attributes").
pub const AFAS_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:afas:1.0:User";

/// One user as a SCIM object. Optional fields without a value are
/// omitted (not sent as null); see README on 'clear attribute values'.
pub fn user_data(r: &PlannedRecord) -> Value {
    let e = &r.employee;
    let mut data = Map::new();
    data.insert("schemas".into(), json!([CORE_SCHEMA, ENTERPRISE_SCHEMA]));
    data.insert("externalId".into(), json!(e.employee_id));
    data.insert("userName".into(), json!(e.upn));
    data.insert(
        "name".into(),
        json!({ "givenName": e.given_name, "familyName": e.family_name }),
    );
    data.insert("displayName".into(), json!(e.display_name));
    if let Some(t) = &e.job_title {
        data.insert("title".into(), json!(t));
    }
    if let Some(mail) = &e.email {
        data.insert(
            "emails".into(),
            json!([{ "value": mail, "type": "work", "primary": true }]),
        );
    }
    if let Some(p) = &e.extra.phone_work {
        data.insert(
            "phoneNumbers".into(),
            json!([{ "value": p, "type": "work" }]),
        );
    }
    if let Some(t) = &e.extra.employee_type {
        data.insert("userType".into(), json!(t));
    }
    let mut addr = Map::new();
    for (k, v) in [
        ("streetAddress", &e.extra.street),
        ("postalCode", &e.extra.postal_code),
        ("locality", &e.extra.city),
        ("country", &e.extra.country),
    ] {
        if let Some(v) = v {
            addr.insert(k.into(), json!(v));
        }
    }
    if !addr.is_empty() {
        addr.insert("type".into(), json!("work"));
        data.insert("addresses".into(), json!([Value::Object(addr)]));
    }
    data.insert("active".into(), json!(r.active));

    let mut ent = Map::new();
    ent.insert("employeeNumber".into(), json!(e.employee_id));
    if let Some(d) = &e.department {
        ent.insert("department".into(), json!(d));
    }
    if let Some(c) = &e.cost_center {
        ent.insert("costCenter".into(), json!(c));
    }
    if let Some(m) = &r.manager_id {
        ent.insert("manager".into(), json!({ "value": m }));
    }
    if let Some(c) = &e.extra.company {
        ent.insert("organization".into(), json!(c));
    }
    data.insert(ENTERPRISE_SCHEMA.into(), Value::Object(ent));

    let mut afas = Map::new();
    if let Some(m) = &e.extra.phone_mobile {
        afas.insert("mobilePhone".into(), json!(m));
    }
    if let Some(o) = &e.extra.office {
        afas.insert("officeLocation".into(), json!(o));
    }
    if let Some(j) = &e.extra.job_profile {
        afas.insert("jobProfile".into(), json!(j));
    }
    if r.send_hire_date {
        afas.insert("hireDate".into(), json!(e.start_date.to_string()));
    }
    if r.send_leave_date
        && let Some(end) = e.end_date
    {
        afas.insert("leaveDate".into(), json!(end.to_string()));
    }
    if !afas.is_empty() {
        data.insert(
            "schemas".into(),
            json!([CORE_SCHEMA, ENTERPRISE_SCHEMA, AFAS_SCHEMA]),
        );
        data.insert(AFAS_SCHEMA.into(), Value::Object(afas));
    }
    Value::Object(data)
}

/// One attribute the tool sends: stable key (as stored in the state), label for people,
/// and the AD attribute the default mapping of the provisioning app writes it to.
pub struct Attribute {
    pub key: &'static str,
    pub label: &'static str,
    pub ad: &'static str,
}

const fn attr(key: &'static str, label: &'static str, ad: &'static str) -> Attribute {
    Attribute { key, label, ad }
}

/// Every attribute, in the order people read them. `active` is not here: it is the action.
pub const ATTRIBUTES: &[Attribute] = &[
    attr("userName", "Sign-in name (UPN)", "userPrincipalName"),
    attr("displayName", "Display name", "displayName"),
    attr("givenName", "Given name", "givenName"),
    attr("familyName", "Family name", "sn"),
    attr("title", "Job title", "title"),
    attr("department", "Department", "department"),
    attr("manager", "Manager", "manager"),
    attr("email", "Email", "mail"),
    attr("phoneWork", "Work phone", "telephoneNumber"),
    attr("mobilePhone", "Mobile", "mobile"),
    attr("officeLocation", "Office", "physicalDeliveryOfficeName"),
    attr("organization", "Company", "company"),
    attr("userType", "Employee type", "employeeType"),
    attr("costCenter", "Cost center", "costCenter mapping"),
    attr("jobProfile", "Job profile", "jobProfile mapping"),
    attr("streetAddress", "Street", "streetAddress"),
    attr("postalCode", "Postal code", "postalCode"),
    attr("locality", "City", "l"),
    attr("country", "Country", "c"),
    attr("hireDate", "Hire date", "hireDate mapping"),
    attr("leaveDate", "Leave date", "leaveDate mapping"),
];

pub fn attribute(key: &str) -> Option<&'static Attribute> {
    ATTRIBUTES.iter().find(|a| a.key == key)
}

/// The values this record sends, flat (attribute key → value). Exactly what `user_data`
/// puts in the payload, so a difference here is a difference Microsoft receives.
/// For the manager: the manager's employee number.
pub fn sent_values(r: &PlannedRecord) -> std::collections::BTreeMap<String, String> {
    let e = &r.employee;
    let mut m = std::collections::BTreeMap::new();
    let mut put = |k: &str, v: Option<&String>| {
        if let Some(v) = v {
            m.insert(k.to_string(), v.clone());
        }
    };
    put("userName", Some(&e.upn));
    put("displayName", Some(&e.display_name));
    put("givenName", Some(&e.given_name));
    put("familyName", Some(&e.family_name));
    put("title", e.job_title.as_ref());
    put("department", e.department.as_ref());
    put("manager", r.manager_id.as_ref());
    put("email", e.email.as_ref());
    put("phoneWork", e.extra.phone_work.as_ref());
    put("mobilePhone", e.extra.phone_mobile.as_ref());
    put("officeLocation", e.extra.office.as_ref());
    put("organization", e.extra.company.as_ref());
    put("userType", e.extra.employee_type.as_ref());
    put("costCenter", e.cost_center.as_ref());
    put("jobProfile", e.extra.job_profile.as_ref());
    put("streetAddress", e.extra.street.as_ref());
    put("postalCode", e.extra.postal_code.as_ref());
    put("locality", e.extra.city.as_ref());
    put("country", e.extra.country.as_ref());
    if r.send_hire_date {
        m.insert("hireDate".into(), e.start_date.to_string());
    }
    if r.send_leave_date
        && let Some(end) = e.end_date
    {
        m.insert("leaveDate".into(), end.to_string());
    }
    m
}

/// Builds bulk requests of at most `batch_size` (1..=50) operations.
pub fn bulk_requests(records: &[PlannedRecord], batch_size: usize) -> Vec<Value> {
    assert!((1..=50).contains(&batch_size), "batch_size must be 1..=50");
    records
        .chunks(batch_size)
        .map(|chunk| {
            let ops: Vec<Value> = chunk
                .iter()
                .map(|r| {
                    json!({
                        "method": "POST",
                        "bulkId": r.employee.employee_id,
                        "path": "/Users",
                        "data": user_data(r),
                    })
                })
                .collect();
            json!({ "schemas": [BULK_SCHEMA], "Operations": ops, "failOnErrors": null })
        })
        .collect()
}
