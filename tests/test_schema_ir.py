from varql.schema_ir import SchemaIR


def test_schema_ir_to_dict():
    schema = SchemaIR(schema_id="seed-1", family_id="cwe-079-xss", summary="demo")
    data = schema.to_dict()
    assert data["schema_id"] == "seed-1"
    assert data["family_id"] == "cwe-079-xss"
    assert data["summary"] == "demo"
