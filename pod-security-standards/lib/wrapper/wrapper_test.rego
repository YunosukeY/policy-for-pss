package lib.wrapper

import future.keywords

test_is_gatekeeper if {
	input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	not is_gatekeeper with input as input
}

test_is_gatekeeper if {
	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	is_gatekeeper with input as input
}

test_resource if {
	input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	resource(input) == input with input as input
}

test_resource if {
	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	resource(input) == input.review.object with input as input
}

test_format if {
	input := {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}
	format("test: %s", ["value"]) == "test: value" with input as input
}

test_format if {
	input := {"review": {"object": {
		"kind": "Pod",
		"metadata": {"name": "myapp-pod"},
	}}}
	format("test: %s", ["value"]) == {"msg": "test: value"} with input as input
}
