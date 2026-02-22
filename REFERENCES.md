# References (External Links & Dependencies)

This file lists external references found in the repository source (HTML/JS/Python/Docs) and the project’s declared dependencies.

## Frontend (CDNs / External Assets)

- Font Awesome (CSS via cdnjs)
  - https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css
- Google Fonts (Outfit)
  - https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap
- Chart.js (via jsDelivr)
  - https://cdn.jsdelivr.net/npm/chart.js
- Leaflet (via unpkg)
  - https://unpkg.com/leaflet@1.9.4/dist/leaflet.css
  - https://unpkg.com/leaflet@1.9.4/dist/leaflet.js
- vis-network (via unpkg)
  - https://unpkg.com/vis-network/standalone/umd/vis-network.min.js
- jQuery (via code.jquery.com)
  - https://code.jquery.com/jquery-3.6.0.min.js
- DataTables (via cdn.datatables.net)
  - https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css
  - https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js

## Maps / Tiles

- CARTO basemap tiles (used by Leaflet)
  - https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png

## External Sites Embedded / Linked

- MITRE ATT&CK
  - https://attack.mitre.org/
  - https://attack.mitre.org/techniques/
- Unsplash images (login/register/admin login backgrounds)
  - https://images.unsplash.com/photo-1451187580459-43490279c0fa
  - https://images.unsplash.com/photo-1555949963-ff9fe0c870eb
  - https://images.unsplash.com/photo-1558494949-ef010cbdcc31
- Wikimedia (image used on landing)
  - https://upload.wikimedia.org/wikipedia/commons/thumb/6/6f/Octicons-shield.svg/1200px-Octicons-shield.svg.png
- GitHub (linked from landing)
  - https://github.com/sentinelhive

## Backend Integrations (Third‑Party Services)

- MobSF Live (Mobile Security Framework) default base URL
  - https://mobsf.live
  - http://mobsf.live

## Supabase (Service Used)

Supabase is used by the backend and worker via environment variables (e.g., `SUPABASE_URL`, `SUPABASE_KEY`) and SQL schema under `supabase/`.

- Supabase homepage
  - https://supabase.com/
- Supabase docs
  - https://supabase.com/docs

## Local Development Endpoints (Repo Defaults)

- Backend API base
  - http://localhost:8000/api/v1
- Frontend → backend paths seen in UI
  - http://localhost:8000/api/v1/mobsf-proxy/
- CORS/dev origins referenced in backend
  - http://localhost
  - http://localhost:8000
  - http://localhost:5500
  - http://localhost:3000
  - http://127.0.0.1:5500
  - http://127.0.0.1:3000

## Sample / Placeholder Domains Found In Schemas & UI Examples

These appear as example payloads or placeholders (not production endpoints):

- http://malicious.com/worm.sh
- http://185.10.x.x/bot.sh
- http://185.x.x.x/bins/x86

## Node.js Dependencies (Declared)

From `services/api/package.json`:

- fastify — https://www.npmjs.com/package/fastify
- @fastify/rate-limit — https://www.npmjs.com/package/@fastify/rate-limit
- jose — https://www.npmjs.com/package/jose
- zod — https://www.npmjs.com/package/zod
- pino — https://www.npmjs.com/package/pino
- dotenv — https://www.npmjs.com/package/dotenv
- typescript (dev) — https://www.npmjs.com/package/typescript
- ts-node (dev) — https://www.npmjs.com/package/ts-node

From `services/worker/package.json`:

- @supabase/supabase-js — https://www.npmjs.com/package/@supabase/supabase-js
- pino — https://www.npmjs.com/package/pino
- dotenv — https://www.npmjs.com/package/dotenv
- typescript (dev) — https://www.npmjs.com/package/typescript
- ts-node (dev) — https://www.npmjs.com/package/ts-node

## Python Dependencies (Declared)

From `backend/requirements.txt`:

- fastapi — https://pypi.org/project/fastapi/
- uvicorn — https://pypi.org/project/uvicorn/
- supabase — https://pypi.org/project/supabase/
- python-dotenv — https://pypi.org/project/python-dotenv/
- pydantic — https://pypi.org/project/pydantic/
- python-multipart — https://pypi.org/project/python-multipart/
- email-validator — https://pypi.org/project/email-validator/
- jinja2 — https://pypi.org/project/Jinja2/
- psutil — https://pypi.org/project/psutil/
- pydantic-settings — https://pypi.org/project/pydantic-settings/
- PyJWT — https://pypi.org/project/PyJWT/
- requests — https://pypi.org/project/requests/

## NPM Registry / Lockfile Resolved URLs

The lockfiles include many machine-generated `resolved` tarball links under:

- https://registry.npmjs.org/

See:
- `services/api/package-lock.json`
- `services/worker/package-lock.json`

## Misc (Appears in lockfile metadata)

- dotenvx site (dependency metadata)
  - https://dotenvx.com
- Sponsors / funding links (dependency metadata)
  - https://github.com/sponsors/fastify
  - https://opencollective.com/fastify
  - https://github.com/sponsors/epoberezkin
  - https://github.com/sponsors/panva
  - https://github.com/sponsors/colinhacks
