# pi-sentinel-interface

An Edge-Based Network Intrusion Detection System (NIDS) local dashboard with a
mock traffic simulator. A virtual Raspberry Pi sends batched packet metadata to
a Flask API, and a dark-mode dashboard polls the API every 2 seconds.

```
pi-sentinel-interface/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   └── index.html
├── simulator/
│   └── mock_traffic.py
└── README.md
```

## Prerequisites

- Python 3.9+
- (Optional) PostgreSQL. If it is not running, the backend automatically falls
  back to an in-memory mock mode, so you can run everything without a database.

## 1. Create a virtual environment

From the project root:

**macOS / Linux**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

## 2. Install requirements

```bash
pip install -r backend/requirements.txt
```

## 3. Run the Flask backend

```bash
python backend/app.py
```

The API listens on `http://localhost:5000`. The startup log tells you which
storage mode is active:

- `Connected to PostgreSQL...` means persistent storage.
- `Falling back to in-memory MOCK mode` means PostgreSQL was not reachable.

### Optional: use PostgreSQL

Create a database and point the backend at it:

```bash
createdb pi_sentinel

# macOS / Linux
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/pi_sentinel"

# Windows (PowerShell)
$env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/pi_sentinel"

python backend/app.py
```

Tables are created automatically. To force mock mode regardless of PostgreSQL,
set `FORCE_MOCK=1`.

## 4. Start the mock traffic simulator

Open a second terminal, activate the same virtual environment, then run:

```bash
python simulator/mock_traffic.py
```

It sends a batch of randomized TCP/UDP/ICMP/ARP packet metadata to
`http://localhost:5000/api/v1/logs` every 2 seconds. Useful flags:

```bash
python simulator/mock_traffic.py --url http://localhost:5000/api/v1/logs --interval 2
```

## 5. Open the dashboard

Open `frontend/index.html` directly in your browser (double-click it), or serve
it:

```bash
python -m http.server 8080 --directory frontend
# then visit http://localhost:8080
```

The connection dot turns green when the dashboard reaches the backend.

## API reference

### `POST /api/v1/logs`

Body: a list of packets, or `{ "node_id": "...", "logs": [ ... ] }`.

```json
{
  "node_id": "pi-sentinel-node-01",
  "logs": [
    {
      "timestamp": "2026-11-08T12:00:00Z",
      "source_ip": "192.168.1.10",
      "destination_ip": "8.8.8.8",
      "protocol": "UDP",
      "packet_size": 74
    }
  ]
}
```

`protocol` must be one of `TCP`, `UDP`, `ICMP`, `ARP`.

### `GET /api/v1/dashboard-stats`

Returns `total_packets`, `unique_ips`, `protocol_distribution`, `recent_logs`,
`node_status`, and `storage_mode`.

### `GET /api/v1/health`

Simple health check.

## Moving to the cloud later

Open `frontend/index.html` and edit the `CONFIG` object at the top of the script:

```js
const CONFIG = {
  API_BASE_URL: "https://your-cloud-host.example.com",
  ...
};
```

Point the simulator (or the real Pi) at the new host with `--url`.

## Troubleshooting

- **Dashboard shows "Disconnected":** make sure `python backend/app.py` is running and `API_BASE_URL` matches its address.
- **Simulator says "backend unreachable":** start the backend first. The simulator retries automatically.
- **PostgreSQL errors at startup:** the app falls back to mock mode. Check `DATABASE_URL` if you want persistent storage.
- **Port 5000 already in use (macOS AirPlay Receiver):** run the backend with `PORT=5001 python backend/app.py`, then update `API_BASE_URL` in `index.html` and use `--url http://localhost:5001/api/v1/logs` for the simulator.
