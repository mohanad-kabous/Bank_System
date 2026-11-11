/*
 * Simple Bank System in C
 * -----------------------
 * Features: create account, PIN login (3-strike lockout), deposit, withdraw,
 *           transfer, transaction history, change PIN, close account.
 * Storage : binary files (accounts.dat, transactions.dat) in the current dir.
 * Money   : stored as integer cents (never use floating point for money).
 *
 * Build: gcc -std=c11 -Wall -Wextra -O2 -o bank bank.c
 * Run  : ./bank
 *
 * NOTE: the PIN hash (salted FNV-1a) is for demonstration only. A real
 * system must use a slow KDF such as Argon2/bcrypt and a database with
 * proper transactions/locking.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#define ACCOUNTS_FILE "accounts.dat"
#define TX_FILE       "transactions.dat"
#define MAX_NAME      50
#define MAX_ATTEMPTS  3
#define MAX_AMOUNT    100000000000LL   /* $1,000,000,000.00 in cents */
#define SALT          "B4nk$alt-2026"

typedef struct {
    int       id;
    char      name[MAX_NAME];
    uint64_t  pin_hash;
    long long balance;      /* cents */
    int       failed;       /* consecutive failed logins */
    int       locked;
    int       active;
} Account;

typedef struct {
    int       account_id;
    int       other_id;     /* counterparty for transfers, else 0 */
    char      type[16];
    long long amount;
    long long balance_after;
    time_t    ts;
} Transaction;

static Account *accts = NULL;
static size_t   n_accts = 0, cap_accts = 0;
static int      next_id = 1001;

/* ---------- utilities ---------- */

static void read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) {          /* EOF -> exit cleanly */
        printf("\nGoodbye.\n");
        exit(0);
    }
    buf[strcspn(buf, "\r\n")] = '\0';
}

static int read_int(const char *prompt) {
    char buf[32], *end;
    for (;;) {
        read_line(prompt, buf, sizeof buf);
        long v = strtol(buf, &end, 10);
        if (end != buf && *end == '\0' && v >= 0 && v <= 2000000000L)
            return (int)v;
        printf("  Invalid number.\n");
    }
}

/* Parses "123.45" into cents. Returns -1 on invalid input. */
static long long read_money(const char *prompt) {
    char buf[64], *end;
    for (;;) {
        read_line(prompt, buf, sizeof buf);
        double d = strtod(buf, &end);
        if (end != buf && *end == '\0' && d > 0 && d <= MAX_AMOUNT / 100.0)
            return llround(d * 100.0);
        printf("  Enter a positive amount (max 1,000,000,000.00).\n");
    }
}

static void print_money(long long cents) {
    printf("$%lld.%02lld", cents / 100, cents % 100);
}

static uint64_t hash_pin(const char *pin) {
    uint64_t h = 1469598103934665603ULL;               /* FNV-1a 64-bit */
    const char *parts[2] = { SALT, pin };
    for (int p = 0; p < 2; p++)
        for (const char *s = parts[p]; *s; s++) {
            h ^= (unsigned char)*s;
            h *= 1099511628211ULL;
        }
    return h;
}

static int valid_pin(const char *pin) {
    if (strlen(pin) != 4) return 0;
    for (int i = 0; i < 4; i++) if (!isdigit((unsigned char)pin[i])) return 0;
    return 1;
}

static void read_pin(const char *prompt, char *pin) {
    for (;;) {
        read_line(prompt, pin, 16);
        if (valid_pin(pin)) return;
        printf("  PIN must be exactly 4 digits.\n");
    }
}

/* ---------- persistence ---------- */

static void save_accounts(void) {
    FILE *f = fopen(ACCOUNTS_FILE, "wb");
    if (!f) { perror("Cannot save accounts"); return; }
    fwrite(accts, sizeof(Account), n_accts, f);
    fclose(f);
}

static void load_accounts(void) {
    FILE *f = fopen(ACCOUNTS_FILE, "rb");
    if (!f) return;                                    /* first run */
    Account a;
    while (fread(&a, sizeof a, 1, f) == 1) {
        if (n_accts == cap_accts) {
            cap_accts = cap_accts ? cap_accts * 2 : 16;
            Account *tmp = realloc(accts, cap_accts * sizeof *accts);
            if (!tmp) { fprintf(stderr, "Out of memory\n"); exit(1); }
            accts = tmp;
        }
        accts[n_accts++] = a;
        if (a.id >= next_id) next_id = a.id + 1;
    }
    fclose(f);
}

static void log_tx(int id, int other, const char *type,
                   long long amount, long long balance_after) {
    Transaction t;
    memset(&t, 0, sizeof t);
    t.account_id = id;
    t.other_id = other;
    strncpy(t.type, type, sizeof t.type - 1);
    t.amount = amount;
    t.balance_after = balance_after;
    t.ts = time(NULL);
    FILE *f = fopen(TX_FILE, "ab");
    if (!f) { perror("Cannot log transaction"); return; }
    fwrite(&t, sizeof t, 1, f);
    fclose(f);
}

/* ---------- account lookup ---------- */

static Account *find_account(int id) {
    for (size_t i = 0; i < n_accts; i++)
        if (accts[i].id == id && accts[i].active) return &accts[i];
    return NULL;
}

/* ---------- operations ---------- */

static void create_account(void) {
    char name[MAX_NAME], pin[16], pin2[16];
    read_line("Full name: ", name, sizeof name);
    if (name[0] == '\0') { printf("  Name cannot be empty.\n"); return; }
    read_pin("Choose a 4-digit PIN: ", pin);
    read_pin("Confirm PIN: ", pin2);
    if (strcmp(pin, pin2) != 0) { printf("  PINs do not match.\n"); return; }

    if (n_accts == cap_accts) {
        cap_accts = cap_accts ? cap_accts * 2 : 16;
        Account *tmp = realloc(accts, cap_accts * sizeof *accts);
        if (!tmp) { printf("  Out of memory.\n"); return; }
        accts = tmp;
    }
    Account *a = &accts[n_accts++];
    memset(a, 0, sizeof *a);
    a->id = next_id++;
    snprintf(a->name, sizeof a->name, "%s", name);
    a->pin_hash = hash_pin(pin);
    a->active = 1;
    save_accounts();
    printf("  Account created. Your account number is %d\n", a->id);
}

static Account *login(void) {
    int id = read_int("Account number: ");
    Account *a = find_account(id);
    if (!a) { printf("  Account not found.\n"); return NULL; }
    if (a->locked) { printf("  Account locked. Contact the bank.\n"); return NULL; }

    char pin[16];
    read_line("PIN: ", pin, sizeof pin);
    if (hash_pin(pin) == a->pin_hash) {
        a->failed = 0;
        save_accounts();
        return a;
    }
    a->failed++;
    if (a->failed >= MAX_ATTEMPTS) {
        a->locked = 1;
        printf("  Too many failed attempts. Account locked.\n");
    } else {
        printf("  Wrong PIN. %d attempt(s) left.\n", MAX_ATTEMPTS - a->failed);
    }
    save_accounts();
    return NULL;
}

static void deposit(Account *a) {
    long long amt = read_money("Deposit amount: ");
    if (a->balance > MAX_AMOUNT - amt) { printf("  Balance limit exceeded.\n"); return; }
    a->balance += amt;
    save_accounts();
    log_tx(a->id, 0, "DEPOSIT", amt, a->balance);
    printf("  Deposited. New balance: "); print_money(a->balance); printf("\n");
}

static void withdraw(Account *a) {
    long long amt = read_money("Withdraw amount: ");
    if (amt > a->balance) { printf("  Insufficient funds.\n"); return; }
    a->balance -= amt;
    save_accounts();
    log_tx(a->id, 0, "WITHDRAW", amt, a->balance);
    printf("  Withdrawn. New balance: "); print_money(a->balance); printf("\n");
}

static void transfer(Account *a) {
    int to_id = read_int("Recipient account number: ");
    Account *to = find_account(to_id);
    if (!to || to == a) { printf("  Invalid recipient.\n"); return; }
    long long amt = read_money("Transfer amount: ");
    if (amt > a->balance) { printf("  Insufficient funds.\n"); return; }
    if (to->balance > MAX_AMOUNT - amt) { printf("  Recipient limit exceeded.\n"); return; }
    a->balance  -= amt;
    to->balance += amt;
    save_accounts();                                   /* one write = both updates */
    log_tx(a->id, to->id, "TRANSFER_OUT", amt, a->balance);
    log_tx(to->id, a->id, "TRANSFER_IN",  amt, to->balance);
    printf("  Sent to %s (#%d). New balance: ", to->name, to->id);
    print_money(a->balance); printf("\n");
}

static void history(const Account *a) {
    FILE *f = fopen(TX_FILE, "rb");
    if (!f) { printf("  No transactions yet.\n"); return; }
    Transaction t;
    int count = 0;
    printf("\n  %-19s %-13s %-8s %14s %14s\n",
           "Date", "Type", "Other", "Amount", "Balance");
    printf("  ------------------------------------------------------------------------\n");
    while (fread(&t, sizeof t, 1, f) == 1) {
        if (t.account_id != a->id) continue;
        char when[20];
        strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", localtime(&t.ts));
        char other[12] = "-";
        if (t.other_id) snprintf(other, sizeof other, "#%d", t.other_id);
        printf("  %-19s %-13s %-8s %10lld.%02lld %10lld.%02lld\n", when, t.type, other,
               t.amount / 100, t.amount % 100,
               t.balance_after / 100, t.balance_after % 100);
        count++;
    }
    fclose(f);
    if (!count) printf("  (no transactions)\n");
}

static void change_pin(Account *a) {
    char old[16], pin[16], pin2[16];
    read_line("Current PIN: ", old, sizeof old);
    if (hash_pin(old) != a->pin_hash) { printf("  Wrong PIN.\n"); return; }
    read_pin("New 4-digit PIN: ", pin);
    read_pin("Confirm new PIN: ", pin2);
    if (strcmp(pin, pin2) != 0) { printf("  PINs do not match.\n"); return; }
    a->pin_hash = hash_pin(pin);
    save_accounts();
    printf("  PIN changed.\n");
}

/* Returns 1 if the account was closed. */
static int close_account(Account *a) {
    char pin[16], ans[8];
    read_line("Confirm PIN: ", pin, sizeof pin);
    if (hash_pin(pin) != a->pin_hash) { printf("  Wrong PIN.\n"); return 0; }
    if (a->balance > 0) {
        printf("  Balance of "); print_money(a->balance);
        printf(" will be paid out in cash.\n");
    }
    read_line("Really close this account? (yes/no): ", ans, sizeof ans);
    if (strcmp(ans, "yes") != 0) { printf("  Cancelled.\n"); return 0; }
    log_tx(a->id, 0, "CLOSE", a->balance, 0);
    a->balance = 0;
    a->active = 0;
    save_accounts();
    printf("  Account closed.\n");
    return 1;
}

/* ---------- menus ---------- */

static void account_menu(Account *a) {
    for (;;) {
        printf("\n=== %s (#%d) | Balance: ", a->name, a->id);
        print_money(a->balance);
        printf(" ===\n 1) Deposit\n 2) Withdraw\n 3) Transfer\n"
               " 4) History\n 5) Change PIN\n 6) Close account\n 0) Logout\n");
        switch (read_int("Choice: ")) {
            case 1: deposit(a);  break;
            case 2: withdraw(a); break;
            case 3: transfer(a); break;
            case 4: history(a);  break;
            case 5: change_pin(a); break;
            case 6: if (close_account(a)) return; break;
            case 0: return;
            default: printf("  Invalid choice.\n");
        }
    }
}

int main(void) {
    load_accounts();
    for (;;) {
        printf("\n===== BANK SYSTEM =====\n 1) Create account\n 2) Login\n 0) Exit\n");
        switch (read_int("Choice: ")) {
            case 1: create_account(); break;
            case 2: { Account *a = login(); if (a) account_menu(a); break; }
            case 0: free(accts); printf("Goodbye.\n"); return 0;
            default: printf("  Invalid choice.\n");
        }
    }
}