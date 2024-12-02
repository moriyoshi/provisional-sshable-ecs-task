#!/usr/bin/env python
import asyncio
import os
import signal
import sys
from typing import Sequence


async def do_it(ecspresso: str, ecspresso_config_file: str, ecs_cluster: str, args: Sequence[str]) -> None:
  local_port = 22222
  remote_port = 22222

  proc_ecspresso_portforward = await asyncio.create_subprocess_exec(
    ecspresso,
    "exec",
    "--config",
    ecspresso_config_file,
    "--container",
    "default",
    "--port-forward",
    "--port",
    str(remote_port),
    "--local-port",
    str(local_port),
    stdin=asyncio.subprocess.DEVNULL,
    env={
      **os.environ,
      "ECS_CLUSTER": ecs_cluster,
    }
  )

  try:
    print("Waiting for session to get portforwarding ready...")
    while True:
      try:
        _, conn = await asyncio.streams.open_connection("127.0.0.1", local_port)
        break
      except Exception as e:
        if not isinstance(e, ConnectionRefusedError):
          raise
      await asyncio.sleep(1)
    
    conn.close()

    proc_ssh = await asyncio.subprocess.create_subprocess_exec(
      "ssh",
      "-p",
      str(local_port),
      "root@localhost",
      *args,
    )
    await proc_ssh.wait()
    try:
      proc_ecspresso_portforward.send_signal(signal.SIGINT)
    except Exception:
      pass
  finally:
    try:
      proc_ecspresso_portforward.send_signal(signal.SIGINT)
    except Exception:
      pass
    await asyncio.wait_for(proc_ecspresso_portforward.wait(), 10)
    try:
      proc_ecspresso_portforward.terminate()
    except Exception:
      pass

asyncio.run(do_it(
  ecspresso=sys.argv[1],
  ecspresso_config_file=sys.argv[2],
  args=sys.argv[3:],
  ecs_cluster=os.environ["ECS_CLUSTER"],
))