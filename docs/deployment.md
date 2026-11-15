# Running and deployment

## Local

Install the project and start the single dashboard:

```powershell
python -m pip install -e .
python src/app.py
```

Open `http://127.0.0.1:5000`. The app generates an ephemeral secret if `SECRET_KEY` is unset. For a stable local value, create a `.env` file containing `SECRET_KEY=` followed by a long random string.

## Docker

```sh
docker build -t signal-flow .
docker run --rm -p 5000:5000 -e SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" signal-flow
```

The Docker image runs one Gunicorn worker with a small thread pool and uses the shared threaded WSGI app. It does not enable live packet capture.

## Render

`render.yaml` defines a web service, health check, generated `SECRET_KEY`, secure cookie setting, and the public-host notice. Connect the project to a GitHub repository in Render and create a Blueprint instance from `render.yaml`. The public notice is required because uploaded PCAPs are sent to the hosted server for in-memory analysis. Keep the default same-origin policy unless a specific trusted dashboard origin is needed.

This workspace has no Git repository or connected Render account, so no public service has been created and there is no live URL yet. After deployment, add the Render URL to the README.

## Advanced: local live capture

Live sniffing is disabled in the web service. To run a local terminal capture, use an interface available to Scapy and the operating system account's normal packet-capture permissions:

```powershell
python src/live_classify.py --duration 60 --iface "Wi-Fi"
```

Omit `--iface` to use Scapy's default interface. This mode reports opaque flow IDs and scores to the terminal and never writes captured packets to disk.

## Free-tier behavior

Render's free web service sleeps after a period of inactivity, so the first request can take up to a minute while it wakes. Open the live link yourself shortly before showing it to a client, or use a paid instance during a pitch. A 7 MB capture with 100,000 packets analyzes in about 3 seconds and peaks near 300 MB of memory, which fits the 512 MB free limit with little spare room; keep the 25 MB upload cap.

