# Assurance Decision Doctrine

Status: controlled static implementation
Data class: synthetic and non-production

## Outcomes

- DENY
- FAIL-CLOSED
- NO-BIND
- HOLD
- ALLOW

## Precedence

DENY > FAIL-CLOSED > NO-BIND > HOLD > ALLOW

## Rule

ALLOW is permitted only when no higher-precedence condition exists.
