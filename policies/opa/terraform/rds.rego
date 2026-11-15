# Databases: encrypted at rest, never publicly accessible, deletion protection recommended.
package terraform.rds

import data.terraform.lib
import rego.v1

db_types := {"aws_db_instance", "aws_rds_cluster"}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type in db_types
	not lib.unknown(rc, "storage_encrypted")
	object.get(rc.change.after, "storage_encrypted", false) != true
	msg := sprintf("%s must set storage_encrypted = true", [rc.address])
}

deny contains msg if {
	some rc in lib.resources_changing
	rc.type == "aws_db_instance"
	rc.change.after.publicly_accessible == true
	msg := sprintf("%s must not be publicly_accessible", [rc.address])
}

warn contains msg if {
	some rc in lib.resources_changing
	rc.type in db_types
	object.get(rc.change.after, "deletion_protection", false) != true
	msg := sprintf("%s should enable deletion_protection", [rc.address])
}
