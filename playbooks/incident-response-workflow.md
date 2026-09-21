# Incident response workflow

## Intake

Record the alert ID, source, affected user, affected device, severity, first seen time, and current status. Keep tenant and customer details out of public notes.

## Triage

Use the highest confirmed signal, not the most dramatic alert title. A high-severity execution alert with a real process tree should outrank a low-context identity anomaly.

Required checks:

- Confirm the affected identity and endpoint owner.
- Review device criticality and department from inventory.
- Capture process tree, sign-in detail, file path, hash, and alert timeline where available.
- Separate confirmed facts from hypotheses.

## Containment decision

Containment should be proportional. Use device isolation or session revocation when signals point to active compromise, credential theft, or unsafe lateral movement risk. Use monitoring and owner confirmation for low-context events.

## Evidence handling

Save generated reports, source exports, timestamps, and analyst notes. Do not store secrets, live tokens, private mailbox content, or customer data in this repository.

## Closure

Close only when the alert has an owner, the containment decision is recorded, remaining risk is stated, and follow-up work is assigned.
