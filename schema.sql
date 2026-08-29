CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Customer', 'Repair Staff'))
);

CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    device_category TEXT NOT NULL
        CHECK (device_category IN ('Phone', 'Tablet', 'Laptop')),
    device_make_model TEXT NOT NULL CHECK (trim(device_make_model) <> ''),
    issue_description TEXT NOT NULL CHECK (trim(issue_description) <> ''),
    status TEXT NOT NULL DEFAULT 'Submitted'
        CHECK (
            status IN (
                'Submitted',
                'Accepted',
                'Rejected',
                'In Progress',
                'Completed',
                'Cancelled'
            )
        ),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES users (id)
);
