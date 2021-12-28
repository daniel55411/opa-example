package http.authz

import data.initial.roles.permissions as initial_roles_permissions
import data.initial.roles.bindings as initial_roles_users
import data.external.roles.bindings as external_roles_users

check_permission(roles_users) {
    roles := roles_users[input.user]
    role := roles[_]
    permissions := initial_roles_permissions[role]
    permission := permissions[_]
    permission == {"action": input.action, "object": input.object}
}

default allow = false

allow {
    check_permission(initial_roles_users)
}

allow {
    check_permission(external_roles_users)
}
