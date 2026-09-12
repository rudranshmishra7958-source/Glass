import docker
import uuid
import time
import json


def run_code(code: str):
    client = docker.from_env()
    container = None

    start_time = time.time()

    monitor = r'''
import sys
import json

events = []
monitoring = False


def audit_hook(event, args):
    global monitoring

    # Ignore Python startup/import activity
    if not monitoring:
        return

    interesting = {
        "open": "File access attempted",
        "socket.__new__": "Network socket created",
        "socket.connect": "Network connection attempted",
        "subprocess.Popen": "Process creation attempted",
        "os.system": "Shell command attempted",
        "os.exec": "Process execution attempted",
        "os.fork": "Process fork attempted",
    }

    if event in interesting:
        events.append({
            "type": event,
            "message": interesting[event]
        })


sys.addaudithook(audit_hook)


# Start monitoring only immediately before user code
monitoring = True

try:
    exec(
        compile(CODE, "<sandbox>", "exec"),
        {"__name__": "__main__"}
    )
except Exception as e:
    print("SAFEBOX_ERROR:" + repr(e))

# Stop monitoring
monitoring = False

print("SAFEBOX_EVENTS:" + json.dumps(events))
'''

    encoded_code = json.dumps(code)
    monitor = monitor.replace("CODE", encoded_code)

    try:
        container = client.containers.run(
            "python:3.12-slim",
            ["python", "-c", monitor],

            name=f"safebox-{uuid.uuid4().hex[:8]}",
            detach=True,
            remove=False,

            # Network isolation
            network_disabled=True,

            # Resource limits
            mem_limit="128m",
            nano_cpus=500_000_000,
            pids_limit=50,

            # Container hardening
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            read_only=True,

            tmpfs={
                "/tmp": "rw,noexec,nosuid,size=16m"
            },
        )

        try:
            result = container.wait(timeout=10)
            timed_out = False
        except Exception:
            container.kill()
            result = {"StatusCode": -1}
            timed_out = True

        raw_output = container.logs().decode(errors="replace")

        execution_time = round(
            time.time() - start_time,
            3
        )

        # Extract behavior events
        events = []

        for line in raw_output.splitlines():
            if line.startswith("SAFEBOX_EVENTS:"):
                try:
                    events = json.loads(
                        line[len("SAFEBOX_EVENTS:"):]
                    )
                except json.JSONDecodeError:
                    pass

        # Extract program output
        output_lines = []

        for line in raw_output.splitlines():
            if not line.startswith("SAFEBOX_EVENTS:"):
                output_lines.append(line)

        output = "\n".join(output_lines)

        # Remove internal SafeBox error prefix from displayed output
        output = output.replace("SAFEBOX_ERROR:", "")

        # Determine execution status
        if timed_out:
            status = "timeout"
        elif "SAFEBOX_ERROR:" in raw_output:
            status = "failed"
        elif result["StatusCode"] == 0:
            status = "completed"
        else:
            status = "failed"

        # Count unique behavior types
        event_types = {event["type"] for event in events}
        event_count = len(events)

        # Risk assessment
        if any(
            event_type in event_types
            for event_type in [
                "socket.connect",
                "socket.__new__",
                "subprocess.Popen",
                "os.system",
                "os.exec",
                "os.fork",
            ]
        ):
            risk = "HIGH"

        elif "open" in event_types:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        return {
            "status": status,
            "exit_code": result["StatusCode"],
            "output": output,
            "execution_time": execution_time,

            "security": {
                "sandboxed": True,
                "network": "blocked",
                "memory_limit": "128MB",
                "process_limit": 50,
            },

            "analysis": {
                "risk": risk,
                "events": events,
                "event_count": event_count,
            },
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }

    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
