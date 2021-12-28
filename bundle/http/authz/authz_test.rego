package http.authz

test_deny_unknown_user {
    not allow with input as {"user": "not_alice", "action": "read", "object": "webdata1"}
}

test_deny_add_user {
    not allow with input as {"user": "not_alice", "action": "read", "object": "webdata1"}
    allow with input as {"user": "not_alice", "action": "read", "object": "webdata1"}
        with data.external.roles.bindings as {"not_alice": ["rang1"]}
}

test_deny_read_webdata2_as_bob {
    not allow with input as {"user": "bob", "action": "read", "object": "webdata2"}
}

test_allow_read_webdata1_as_bob {
    allow with input as {"user": "bob", "action": "read", "object": "webdata1"}
}

test_allow_read_any_webdata_as_alice {
    allow with input as {"user": "alice", "action": "read", "object": "webdata1"}
    allow with input as {"user": "alice", "action": "read", "object": "webdata2"}
}

test_deny_non_exist_action {
    not allow with input as {"user": "bob", "action": "write", "object": "webdata2"}
}

test_deny_non_exist_resource {
    not allow with input as {"user": "bob", "action": "read", "object": "any"}
}
