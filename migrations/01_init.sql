CREATE TABLE users (
    username TEXT PRIMARY KEY NOT NULL,
    password TEXT NOT NULL
);
 
CREATE TABLE progress (
    document TEXT NOT NULL,
    username TEXT NOT NULL,
    device TEXT NOT NULL,
    device_id TEXT NOT NULL,
    progress TEXT NOT NULL,
    percentage REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (document, username)
);