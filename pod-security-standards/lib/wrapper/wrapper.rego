package lib.wrapper

import future.keywords

default is_gatekeeper = false

is_gatekeeper if {
	input.review.object
}

resource(object) := object.review.object if {
	is_gatekeeper
}

resource(object) := object if {
	not is_gatekeeper
}

format(format, value) := output if {
	is_gatekeeper
	output := {"msg": sprintf(format, value)}
}

format(format, value) := output if {
	not is_gatekeeper
	output := sprintf(format, value)
}
