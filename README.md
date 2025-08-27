# MuseSphere - Online Art Gallery Platform

MuseSphere is a web-based platform developed as part of the COMP SCI 2207/7207 Web & Database Computing course at the University of Adelaide. It allows users to explore, collect, and manage digital artworks while providing administrative tools for managing users.

---

## Features

### User Features:
- Browse and explore artwork collections
- View detailed profiles of artworks and artists
- Create and manage personal collections
- Like artworks and view curated lists
- Upload profile pictures and manage user settings

---

### Admin Features:
- Add new users with details like username, email, password, and avatar
- Delete existing users by ID
- View a list of all registered users
- Edit user information including username, email, password, and profile picture

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/UAdelaide/25S1_WDC_UG_Groups_56.git
cd 25S1_WDC_UG_Groups_56
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Run the App
```bash
npm start
```

## Database

The project uses SQLite (`musesphere.db`). Ensure this file exists in the root directory before running the app. The `users` table has the following structure:

| Field        | Type     |
|--------------|----------|
| `id`         | INTEGER PRIMARY KEY |
| `username`   | TEXT     |
| `email`      | TEXT     |
| `password`   | TEXT     |
| `profile_pic`| TEXT     |

---

## Project Structure

```
.
├── app.js                  # Main Express server
├── public/                 # Frontend HTML files
├── routes/                 # Express routes (user/admin APIs)
├── musesphere.db           # SQLite database
├── admin.html              # Admin dashboard (in public/)
└── README.md               # Project documentation
```

---

## Known Issues / Limitations

---

## Team Members

- Adelle Ocampo
- Nuwin Sooriyaarachchi
- Akrita Singh
- Iftakhar Rasul Shams

---

## License
This project is for educational purposes only – University of Adelaide, Semester 1 2025.