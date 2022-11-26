#pragma once

#include <stddef.h>     // for size_t
#include <stdint.h>     // for int64_t, uint64_t
#include <string>       // for string
#include <string_view>  // for string_view

#include "error.hh"     // for Error, MakeError
#include "fmt.hh"       // for hintfmt, hintformat
#include "types.hh"     // for Path

struct sqlite3; // IWYU pragma: keep
struct sqlite3_stmt; // IWYU pragma: keep

namespace nix {

/* RAII wrapper to close a SQLite database automatically. */
struct SQLite
{
    sqlite3 * db = 0;
    SQLite() { }
    SQLite(const Path & path, bool create = true);
    SQLite(const SQLite & from) = delete;
    SQLite& operator = (const SQLite & from) = delete;
    SQLite& operator = (SQLite && from) { db = from.db; from.db = 0; return *this; }
    ~SQLite();
    operator sqlite3 * () { return db; }

    /* Disable synchronous mode, set truncate journal mode. */
    void isCache();

    void exec(const std::string & stmt);

    uint64_t getLastInsertedRowId();
};

/* RAII wrapper to create and destroy SQLite prepared statements. */
struct SQLiteStmt
{
    sqlite3 * db = 0;
    sqlite3_stmt * stmt = 0;
    std::string sql;
    SQLiteStmt() { }
    SQLiteStmt(sqlite3 * db, const std::string & sql) { create(db, sql); }
    void create(sqlite3 * db, const std::string & s);
    ~SQLiteStmt();
    operator sqlite3_stmt * () { return stmt; }

    /* Helper for binding / executing statements. */
    class Use
    {
        friend struct SQLiteStmt;
    private:
        SQLiteStmt & stmt;
        unsigned int curArg = 1;
        Use(SQLiteStmt & stmt);

    public:

        ~Use();

        /* Bind the next parameter. */
        Use & operator () (std::string_view value, bool notNull = true);
        Use & operator () (const unsigned char * data, size_t len, bool notNull = true);
        Use & operator () (int64_t value, bool notNull = true);
        Use & bind(); // null

        int step();

        /* Execute a statement that does not return rows. */
        void exec();

        /* For statements that return 0 or more rows. Returns true iff
           a row is available. */
        bool next();

        std::string getStr(int col);
        int64_t getInt(int col);
        bool isNull(int col);
    };

    Use use()
    {
        return Use(*this);
    }
};

/* RAII helper that ensures transactions are aborted unless explicitly
   committed. */
struct SQLiteTxn
{
    bool active = false;
    sqlite3 * db;

    SQLiteTxn(sqlite3 * db);

    void commit();

    ~SQLiteTxn();
};


struct SQLiteError : Error
{
    const char *path;
    int errNo, extendedErrNo;

    template<typename... Args>
    [[noreturn]] static void throw_(sqlite3 * db, const std::string & fs, const Args & ... args) {
        throw_(db, hintfmt(fs, args...));
    }

    SQLiteError(const char *path, int errNo, int extendedErrNo, hintformat && hf);

protected:

    template<typename... Args>
    SQLiteError(const char *path, int errNo, int extendedErrNo, const std::string & fs, const Args & ... args)
      : SQLiteError(path, errNo, extendedErrNo, hintfmt(fs, args...))
    { }

    [[noreturn]] static void throw_(sqlite3 * db, hintformat && hf);

};

MakeError(SQLiteBusy, SQLiteError);

void handleSQLiteBusy(const SQLiteBusy & e);

/* Convenience function for retrying a SQLite transaction when the
   database is busy. */
template<typename T, typename F>
T retrySQLite(F && fun)
{
    while (true) {
        try {
            return fun();
        } catch (SQLiteBusy & e) {
            handleSQLiteBusy(e);
        }
    }
}

}
