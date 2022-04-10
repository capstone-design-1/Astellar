CREATE TABLE target_site (
    target_idx              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain                  TEXT NOT NULL,
    subdomain_search_time   TEXT
);

CREATE TABLE subdomain (
    subdomain_idx         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_idx            INTEGER NOT NULL,
    subdomain             TEXT NOT NULL,
    status_code           INTEGER NOT NULL,
    foreign key (target_idx) references target_site(target_idx)
);

CREATE TABLE todo (
    todo_idx            INTEGER PRIMARY KEY AUTOINCREMENT,
    context             TEXT NOT NULL,
    done                INTEGER NOT NULL default 0
);