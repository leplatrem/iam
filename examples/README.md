# Integration Examples

- [Python / Flask](python/): A Web UI interacts with Auth0 and a Flask API

# Configuration Examples

## Roles from service

A role is a *principal* that usually depends on the relation between a user and a resource. For example, `alice` is the `author` of `articles/42`.

Since it's not the responsibility of the *Identity Provider* nor *Doorman* to manage this relation, the service sends the roles of the current user in the authorization request `context`.

For instance, for a service where objects and users are stored in its database (e.g Django), the service will:

1. verify and read the JWT payload to get the authenticated userid
1. fetch the resource attributes and lookup the user in the database
1. determine the user roles with regards to this object (eg. `author`, `collaborator`, or global `superuser`...)
1. send an authorization request to Doorman with roles in the context field

And Doorman will match rules and determine if the user is allowed to perform the specified action on the specified resource

In the example below, we rely on the groups of given by the *Identity Provider* to allow creating articles, and on the roles provided by the service to determine who can edit them:

```yaml
service: gurghruin435u85O539g7cKvWBOI
identityProvider: https://auth.mozilla.auth0.com/
policies:
  -
    id: create-articles
    description: Members of the moco group can create articles
    principals:
      - group:moco
    actions:
      - create
    resources:
      - article
    effect: allow
  -
    id: edit-articles
    description: Authors and collaborators can edit articles
    principals:
      - role:author
      - role:collaborator
    actions:
      - read
      - update
    resources:
      - article
    effect: allow
  -
    id: super-users
    description: Superusers can do everything
    principals:
      - role:superuser
    actions:
      - <.*>
    resources:
      - <.*>
    effect: allow
```

An authorization request sent from the service can look like this (here, the user is author of the article):

```
curl -s -X POST http://localhost:8080/allowed \
-H "Authorization: Bearer $ACCESS_TOKEN" \
-H "Content-Type: application/json" \
-H "Origin: gurghruin435u85O539g7cKvWBOI"
-d @- << EOF

{
  "action": "update",
  "resource": "article",
  "context": {
    "roles": ["author"]
  }
}
EOF
```

Which in this case returns:

```json
{
  "allowed": true,
  "principals": [
    "userid:mleplatre",
    "role:author",
    "group:moco",
    "group:irccloud",
    "group:vpn",
    "group:cloudservices"
  ]
}
```

- *TODO: add a small Django demo*


## Doorman tags

For example, you want to use Doorman to maintain a carefully curated list of people who should become "superusers" when they log in to a certain service. This means the service doesn't have to rely on an *Identity Provider* nor build the functionality to promote and demote superusers.

To do that, we define a tag `superuser` along with the intended principals in the service configuration. And then in the policies rules, we refer to this tag as the `tag:superuser` principal.

```yaml
service: https://api.service.org
identityProvider:  # disabled
tags:
  superuser:
    - userid:maria
    - group:admins
policies:
  -
    id: super-users
    description: Superusers can do everything
    principals:
      - tag:superuser
    actions:
      - <.*>
    resources:
      - <.*>
    effect: allow
```

In the example above, the userid `maria` or the members of the `admins` group are allowed to perform any action on any resource on the `https://api.service.org` service.

Since in this case we didn't enable authentication, an authorization request specifies the `principals` and looks like this:

```
curl -s -X POST http://localhost:8080/allowed \
-H "Content-Type: application/json" \
-H "Origin: https://api.service.org"
-d @- << EOF

{
  "principals": ["userid:maria", "group:employees", "group:france"]
  "action": "disable",
  "resource": "notifications"
}
EOF
```

Which in this case returns:

```json
{
  "allowed": true,
  "principals": [
    "userid:maria",
    "tag:superuser",
    "group:employees",
    "group:france"
  ]
}
```

## Mozilla specific

*Doorman* is not tied to Mozilla in any other way that its maintainers work at Mozilla. The solutions examples presented in this section are Mozilla specific, but only because they're common among early users of *Doorman*.

### Staff only

Mozilla integrated Auth0 and its HR system so that when users are members of staff, they are given the special group `hris_is_staff`.

Restricting access on a service to the members of staff at Mozilla is thus as simple as:

```yaml
service: SLocf7Sa1ibd5GN
ìdentityProvider: https://auth.mozilla.auth0.com
policies:
  -
    id: staff-only
    description: Staff only
    principals:
      - group:hris_is_staff
    actions:
      - <.*>
    resources:
      - <.*>
    effect: allow
```

### Employees and contractors

Following the same approach as staff, employees and contractors can be differenciated within staff via specific HRIS groups: `hris_workertype_employee` and `hris_workertype_contractor` respectively.
