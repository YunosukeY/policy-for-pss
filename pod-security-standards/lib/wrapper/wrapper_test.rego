package lib.wrapper

import rego.v1

test_is_gatekeeper if {
	test_input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	not is_gatekeeper with input as test_input
}

test_is_gatekeeper if {
	test_input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	is_gatekeeper with input as test_input
}

test_resource if {
	test_input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	resource(input) == input with input as test_input
}

test_resource if {
	test_input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	resource(input) == input.review.object with input as test_input
}

test_format if {
	test_input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	format("test: %s", ["value"]) == "test: value" with input as test_input
}

test_format if {
	test_input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	format("test: %s", ["value"]) == {"msg": "test: value"} with input as test_input
}
