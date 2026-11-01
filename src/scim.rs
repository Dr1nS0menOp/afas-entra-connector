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
