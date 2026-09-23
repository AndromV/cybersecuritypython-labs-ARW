import os
import sys
import tabulate

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
 "cloud_architect": {"role": "cloud_security", "clearance": 4, "department":
"Cloud", "active": True},
 "devops_engineer": {"role": "devops", "clearance": 3, "department":
"DevOps", "active": True},
 "qa_tester": {"role": "quality_assurance", "clearance": 2, "department":
"QA", "active": True},
 "partner_access": {"role": "partner", "clearance": 2, "department":
"Partnership", "active": True},
 "migrated_user": {"role": "migrated", "clearance": 1, "department":
"Migration", "active": False}
}
resources = [("cloud_configs", 4), ("deployment_pipelines", 3),
("test_environments", 2), ("partner_apis", 2), ("infrastructure_code", 4),
("shared_resources", 1), ("container_registry", 3), ("secrets_vault", 4),
("build_artifacts", 2), ("public_endpoints", 1)]
security_levels = ("Development", "Staging", "Production", "CriticalInfrastructure")
blocked_users = {"migrated_user", "container_breach", "pipeline_compromise"}

def main() -> None:
    print(GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER)
    t1_resourses = []
    for r, s_n in resources:
        t1_resourses.append((r, security_levels[s_n - 1]))
    print(
        tabulate.tabulate(
            t1_resourses,
            headers = ["Ресурс", "Рівень Безпеки"],
            showindex = range(1, len(t1_resourses) + 1),
            tablefmt = "grid",
        )
    )
    results = []
    for u, data in users.items():
        for r in resources:
            if u not in users:
                status = "Deny(User not found)"
            elif u in blocked_users:
                status = "Deny(User is blocked)"
            elif data["active"] == False:
                status = "Deny(Accound inactive)"
            elif data["clearance"] >= r[1]:
                status = "Allow"
            elif data["clearance"] < r[1]:
                status = "Deny(Insufficient clearance)"
            else:
                status = "Error"
            results.append((u, r[0], status))
    for user, resource, status in results:
        print(f"user={user} resource={resource} -> {status}")
        
if __name__ == "__main__":
    main()
