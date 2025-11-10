# Superlatives Voting App

A lightweight Flask web application for creating and participating in shared superlative-style votings. Every authenticated user can launch new votings, explore existing ones, and cast a single vote per poll. Results stay hidden until you vote—perfect for fair classroom reveals.

## Features

- User registration and login backed by a SQLite database.
- Create polls with a title, optional description, and dynamically add category inputs (each with an optional image).
- Upload a striking cover image for every voting to spotlight it in the listings.
- Vote once per poll; live results unlock only after you cast your ballot (creators can always review results).
- Opt-in chat lives under each voting and unlocks for participants after they vote; creators can disable chat during setup.
- Browse all votings with sort-by-newest or sort-by-popularity options, plus a dedicated “My Votings” view with a prominent “Create a New Voting” action.
- Elegant UI with a vibrant gradient background that works great on desktop and mobile.

## Getting Started

1. **Install dependencies**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Run the development server**

   ```bash
   flask --app app run --debug
   ```

   The database (`instance/app.db`) is created on first launch. Visit <http://127.0.0.1:5000>.

## Deploying Publicly

- The app relies only on Flask and SQLite, so it works well on platforms such as Render, Railway, PythonAnywhere, or any VPS that supports Python 3.11+.
- Set the environment variable `SECRET_KEY` to a strong random value in production.
- If your host uses a different database, set `DATABASE_URL` accordingly (e.g. `postgresql://...`). SQLAlchemy handles the connection string automatically.

## Project Structure

```
.
├── app.py
├── requirements.txt
├── README.md
├── static/
│   ├── css/
│   │   └── styles.css
│   └── uploads/        # generated at runtime for cover/category images
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── my_polls.html
    ├── new_poll.html
    ├── poll_detail.html
    └── register.html
```

## Notes

- Passwords are stored as hashes using Werkzeug utilities.
- Sessions keep users logged in; use the logout link to end the session.
- Results are calculated fresh on each visit to reflect the latest votes.
- Uploads are saved under `static/uploads/`. Adjust `UPLOAD_FOLDER` or `ALLOWED_EXTENSIONS` via environment variables if needed.
- Create or manage your own votings from the “My Votings” page — the primary action button there launches the creation form.
