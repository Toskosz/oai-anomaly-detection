#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 

/*
* This is a callback function for sqlite3_exec.
* It's not strictly needed for this example but is good to know.
* It gets called for each row returned by the query.
*/
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    int i;
    for(i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int main(int argc, char* argv[]) {
    sqlite3 *db;         // Database handle
    sqlite3_stmt *stmt;  // Prepared statement handle
    char *zErrMsg = 0;   // Error message string
    int rc;              // Result code

    const char *db_path = "test.db";

    // --- 1. Open the database ---
    // This will create 'test.db' if it doesn't exist.
    rc = sqlite3_open(db_path, &db);
    if(rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return(1);
    } else {
        printf("Opened database '%s' successfully.\n\n", db_path);
    }

    // --- 2. Create and populate a table ---
    // We use sqlite3_exec for simple, one-off commands.
    const char *sql_setup = 
        "DROP TABLE IF EXISTS users;"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, status INTEGER);"
        "INSERT INTO users (name, status) VALUES ('Alice', 1);"
        "INSERT INTO users (name, status) VALUES ('Bob', 2);"
        "INSERT INTO users (name, status) VALUES ('Charlie', 1);";

    rc = sqlite3_exec(db, sql_setup, 0, 0, &zErrMsg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error during setup: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        printf("Table 'users' created and populated.\n\n");
    }

    // --- 3. SELECT data ---
    // For queries that return data (SELECT), we use a prepared statement.
    printf("--- Selecting user with status = 2 ---\n");
    const char *sql_select = "SELECT id, name FROM users WHERE status = 2;";
    
    // Prepare the statement
    rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare select statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Execute the statement
    // SQLITE_ROW means we got a row of data
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Get data from the columns (0-indexed)
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        
        printf("Found user: ID = %d, Name = %s\n", id, name);
    }
    printf("--------------------------------------\n\n");

    // Clean up the statement
    sqlite3_finalize(stmt);

    // --- 4. UPDATE data ---
    // We also use a prepared statement for UPDATE, especially if using parameters.
    // Here, we update all users with status 2 to status 3.
    printf("--- Updating user 'Bob' (status 2) to status 3 ---\n");
    const char *sql_update = "UPDATE users SET status = 3 WHERE name = 'Bob';";

    rc = sqlite3_prepare_v2(db, sql_update, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Execute the statement
    // SQLITE_DONE means the statement finished successfully.
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Update failed: %s\n", sqlite3_errmsg(db));
    } else {
        printf("Update successful. %d row(s) changed.\n\n", sqlite3_changes(db));
    }
    
    // Clean up the statement
    sqlite3_finalize(stmt);

    // --- 5. Verify the UPDATE with another SELECT ---
    // We'll use sqlite3_exec with a callback this time to show all data.
    printf("--- Final table contents ---\n");
    const char *sql_select_all = "SELECT * FROM users;";
    rc = sqlite3_exec(db, sql_select_all, callback, 0, &zErrMsg);
    
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        printf("Selection finished.\n");
    }

    // --- 6. Close the database ---
    sqlite3_close(db);
    printf("\nDatabase closed.\n");

    return 0;
}
