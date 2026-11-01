"""Independent evaluator of only the JSON Schema keywords emitted by P3.

This test helper is not a general Draft 2020-12 implementation or a dependency.
It knows nothing about Python contract record classes.
"""


def validate_shape(value, document):
    def visit(value, schema):
        if '$ref' in schema:
            ref = schema['$ref']
            if not ref.startswith('#/$defs/'):
                raise ValueError('Only local schema references are supported by this test helper')
            return visit(value, document['$defs'][ref.split('/')[-1]])
        if 'anyOf' in schema:
            for alternative in schema['anyOf']:
                try:
                    visit(value, alternative)
                    return
                except ValueError:
                    pass
            raise ValueError('No schema alternative matched')
        if 'const' in schema and value != schema['const']:
            raise ValueError('Wrong schema constant')
        if 'enum' in schema and value not in schema['enum']:
            raise ValueError('Unknown enum value')
        expected = schema.get('type')
        python_types = {'string': str, 'integer': int, 'boolean': bool, 'array': list, 'object': dict, 'null': type(None)}
        if expected is not None and type(value) is not python_types[expected]:
            raise ValueError('JSON scalar/container type mismatch')
        if expected == 'object':
            properties = schema.get('properties', {})
            if not set(schema.get('required', ())) <= set(value):
                raise ValueError('Missing required schema field')
            if schema.get('additionalProperties') is False and not set(value) <= set(properties):
                raise ValueError('Unexpected schema field')
            for key, child in value.items():
                if key in properties:
                    visit(child, properties[key])
        if expected == 'array':
            if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', len(value)):
                raise ValueError('Wrong array length')
            if schema.get('uniqueItems') and any(item in value[:i] for i, item in enumerate(value)):
                raise ValueError('Duplicate array items')
            for i, child in enumerate(value):
                prefix = schema.get('prefixItems', ())
                if i < len(prefix):
                    visit(child, prefix[i])
                elif 'items' in schema:
                    visit(child, schema['items'])
    visit(value, document)
