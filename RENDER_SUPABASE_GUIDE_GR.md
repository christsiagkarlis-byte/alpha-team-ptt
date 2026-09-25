# Team Stadium σε Supabase + Render

Αυτός είναι ο απλός οδηγός για να λειτουργήσει η εφαρμογή χωρίς δικό σου VPS.

## Τι θα χρησιμοποιήσεις

- **Supabase:** PostgreSQL βάση.
- **Render:** Node.js, Express και Socket.IO εφαρμογή.
- **Redis-compatible υπηρεσία:** Render Key Value ή Upstash Redis για presence, quotas, PTT locks, rate limiting και προσωρινά WebAuthn challenges.
- **GitHub:** προαιρετικό. Συνιστάται μόνο για εύκολο deploy και backup του κώδικα.

> Το δωρεάν setup είναι κατάλληλο για δοκιμή. Το Render Free service κοιμάται μετά από αδράνεια, το δωρεάν Supabase έχει όρια και το δωρεάν Redis μπορεί να χάσει προσωρινά δεδομένα. Μην χρησιμοποιήσεις το free setup ως μοναδικό σύστημα για πραγματικά επείγοντα SOS.

## Αρχεία που χρειάζεσαι

- `render.yaml`: έτοιμο Render Blueprint.
- `.env.render.example`: λίστα μεταβλητών που θα περάσεις στο Render.
- `supabase/001_team_stadium_schema.sql`: schema που θα εκτελέσεις στο Supabase.
- `package.json` και `package-lock.json`: dependencies και reproducible install.
- Όλος ο υπόλοιπος φάκελος του project: backend, frontend και tests.

## Βήμα 1 — Δημιούργησε Supabase project

1. Άνοιξε το [supabase.com](https://supabase.com) και δημιούργησε νέο project.
2. Αποθήκευσε με ασφάλεια το database password.
3. Άνοιξε το **SQL Editor**.
4. Άνοιξε το αρχείο `supabase/001_team_stadium_schema.sql`.
5. Αντέγραψε όλο το περιεχόμενό του στο SQL Editor και πάτησε **Run**.
6. Έλεγξε στο **Table Editor** ότι δημιουργήθηκαν οι πίνακες.

Για το `DATABASE_URL`, άνοιξε το **Connect** στο Supabase και πάρε τη σύνδεση PostgreSQL από το **Session Pooler**. Μην γράψεις το password σε αρχείο που θα ανέβει στο GitHub.

## Βήμα 2 — Δημιούργησε Redis

Η εφαρμογή δεν χρησιμοποιεί μόνο PostgreSQL. Χρειάζεται Redis-compatible υπηρεσία.

### Επιλογή A — Render Key Value

1. Στο Render πάτησε **New → Key Value**.
2. Επίλεξε το ίδιο region με το Web Service.
3. Για δοκιμή μπορείς να χρησιμοποιήσεις το Free plan, αν είναι διαθέσιμο στον λογαριασμό σου.
4. Αντέγραψε το Redis connection URL ως `REDIS_URL`.

### Επιλογή B — Upstash Redis

1. Δημιούργησε Redis database στο Upstash.
2. Αντέγραψε το `rediss://...` URL.
3. Χρησιμοποίησέ το ως `REDIS_URL` στο Render.

## Βήμα 3 — Ανέβασε τον κώδικα

Το GitHub δεν είναι υποχρεωτικό, αλλά είναι ο απλούστερος τρόπος για Render.

1. Δημιούργησε ένα **private repository**.
2. Ανέβασε τον φάκελο του project.
3. Μην ανεβάσεις ποτέ `.env`, πραγματικά passwords, JWT secrets, admin key ή access code.
4. Αν δεν θέλεις GitHub, μπορείς να χρησιμοποιήσεις άλλο Git provider ή Docker image deployment που υποστηρίζει το Render.

## Βήμα 4 — Δημιούργησε Render Web Service

1. Άνοιξε το [Render Dashboard](https://dashboard.render.com).
2. Πάτησε **New → Blueprint** ή **New → Web Service**.
3. Συνέδεσε το repository.
4. Αν χρησιμοποιήσεις Blueprint, επίλεξε το `render.yaml` του project.
5. Αν το κάνεις χειροκίνητα, χρησιμοποίησε:

```text
Runtime: Node
Build command: npm ci --omit=dev --ignore-scripts
Start command: npm start
Health check path: /health
```

Το `render.yaml` έχει `PORT=10000`. Η εφαρμογή ακούει στο `0.0.0.0` και στο `PORT` που δίνει το Render.

## Βήμα 5 — Βάλε τα secrets στο Render

Στο Render άνοιξε το Web Service και πήγαινε **Environment → Environment Variables**.

Βάλε τις τιμές από το `.env.render.example`. Τα απολύτως απαραίτητα είναι:

```text
DATABASE_URL
REDIS_URL
JWT_SECRET
ADMIN_API_KEY
ACCESS_CODE
CORS_ORIGIN
WEBAUTHN_RP_ID
WEBAUTHN_ORIGIN
PGSSL=true
TRUST_PROXY=true
```

Για αρχικό test, αν το Render URL είναι:

```text
https://team-stadium.onrender.com
```

τότε χρησιμοποίησε:

```text
CORS_ORIGIN=https://team-stadium.onrender.com
WEBAUTHN_RP_ID=team-stadium.onrender.com
WEBAUTHN_ORIGIN=https://team-stadium.onrender.com
```

Μην βάλεις τελικό slash στο `WEBAUTHN_ORIGIN`.

## Βήμα 6 — Κάνε deploy

Πάτησε **Manual Deploy → Deploy latest commit**. Περίμενε να ολοκληρωθεί το build.

Μετά έλεγξε:

```text
https://team-stadium.onrender.com/health
```

Πρέπει να δεις απάντηση που περιλαμβάνει:

```json
{"status":"ok","database":"ok","redis":"ok","websocket":"ok"}
```

Αν δεις `database: degraded`, έλεγξε το `DATABASE_URL`, το Supabase password και το `PGSSL=true`. Αν δεις `redis: unavailable`, έλεγξε το `REDIS_URL`.

## Βήμα 7 — Έλεγξε την εφαρμογή

1. Άνοιξε το Render URL από κινητό.
2. Δοκίμασε το αρχικό access code.
3. Δοκίμασε enroll ή login.
4. Έλεγξε ότι εμφανίζεται η παρουσία χρηστών.
5. Άνοιξε δύο browsers για Socket.IO/PTT test.
6. Δοκίμασε test SOS μόνο με δοκιμαστικά δεδομένα.
7. Όταν λειτουργήσει, επίλεξε από τον browser **Προσθήκη στην αρχική οθόνη**.

## Αν δεν θέλεις GitHub

Το GitHub είναι προαιρετικό. Χωρίς GitHub, το Render πρέπει να πάρει τον κώδικα από άλλο Git provider ή από Docker image registry. Για αρχάριο, το private GitHub repository είναι η πιο απλή λύση και δεν απαιτεί πληρωμή από μόνο του.

## Τι να μην κάνεις

- Μην ανεβάσεις `.env` στο repository.
- Μην βάλεις το Supabase password μέσα στο `database.sql`.
- Μην ανοίξεις δημόσια τη βάση Supabase χωρίς λόγο.
- Μην αποθηκεύσεις secrets στο frontend `public/`.
- Μην θεωρήσεις το δωρεάν setup αξιόπιστο για κρίσιμες επιχειρήσεις.
- Μην διαγράψεις το Supabase project πριν πάρεις backup.

## Τελική εικόνα

```text
Κινητό χρήστη
      │ HTTPS / Socket.IO
      ▼
Render Web Service
      ├── Node.js / Express
      ├── Socket.IO / WebRTC signaling
      └── Frontend PWA
          │
          ├── DATABASE_URL ──► Supabase PostgreSQL
          └── REDIS_URL ─────► Render Key Value ή Upstash
```
