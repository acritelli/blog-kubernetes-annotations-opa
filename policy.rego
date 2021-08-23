package kubernetes.admission

# Credit to https://github.com/open-policy-agent/opa/issues/1263 for this function
# which just checks to see if there is an element in an array
contains(array, element) {
	array[_] == element
}

# Obtains all of the keys in the annotations of a resource
input_annotation_keys[key] {
    some key
    input.request.object.metadata.annotations[key]
}

# Obtains all of the keys in the annotation of a resources created via a template
# For example: a pod template in a deployment
input_annotation_keys[key] {
    some key
    input.request.object.spec.template.metadata.annotations[key]
}

# Evaluates to true if the key is "payload"
explicitly_denied_annotation_key[key] {
    some key
    input_annotation_keys[key]
    key == "payload"
}

# Deny annotation keys based on a regex match of h2o-*
explicitly_denied_annotation_key[key] {
    some key
    input_annotation_keys[key]
    regex.match("h2O*", key)
}

# Renders an admission decision (deny) with a message if any explicitly denied annotation keys are found
deny[msg] {
    msg := sprintf("Annotation '%v' was found in the explicit deny list", [explicitly_denied_annotation_key[_]])
}

# Regex match for allowed annotations
allowed_annotation_key[key] {
    some key
    input_annotation_keys[key]
    regex.match("container-scanner-*", key)
}

# Allow kubectl annotations
allowed_annotation_key[key] {
    some key
    input_annotation_keys[key]
    regex.match("kubectl.kubernetes.io/*", key)
}

# Literal match for allowed annotations
allowed_annotation_key[key] {
    some key
    input_annotation_keys[key]
    contains(["softeng-team", "oncall-email"], key)
}

# Deny if we have any keys that aren't explicitly allowed
deny[msg] {
    some key
    input_annotation_keys[key]
    not contains(allowed_annotation_key, input_annotation_keys[key])
    msg := sprintf("Annotation '%v' not found in explicitly allowed key list", [key])
}

# Get a list of key/value pairs
input_annotation_kv_pairs[kv_pair] {
     some key
    input_annotation_keys[key]
    value := input.request.object.metadata.annotations[key]
    kv_pair := {"key": key, "value": value}
}

# True if the annotation key is "container-scanner-result"
# AND the value is not passed or failed
denied_annotation_key_value[kv_pair] {
    kv_pair := input_annotation_kv_pairs[_]
    kv_pair.key == "container-scanner-result"
    not regex.match(kv_pair.value, "passed|failed")
}

# Deny the request if any annotations did not have the expected key/value pair
deny[msg] {
    kv_pair := denied_annotation_key_value[_]
    msg := sprintf("The value '%v' is not allowed for key '%v'", [kv_pair.value, kv_pair.key])
}
