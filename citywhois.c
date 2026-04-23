#include "unrealircd.h"
#include <maxminddb.h>
#include <arpa/inet.h>
#include <unistd.h>   // for access()
#include <errno.h>

#define MYCONF "citywhois"

typedef struct {
    char *db_path;
    MMDB_s mmdb;
    int db_loaded;
} CityWhoisConfig;

static CityWhoisConfig citywhois_config;

// Module header
ModuleHeader MOD_HEADER = {
    "third/citywhois",
    "1.1",
    "Show city information in WHOIS",
    "DeviL",
    "unrealircd-6",
};

// Temp storage during config parsing
static char *tmp_db_path = NULL;

// Prototypes
int citywhois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int citywhois_configposttest(int *errs);
int citywhois_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int citywhois_whois(Client *requester, Client *acptr, NameValuePrioList **list);

// -------------------- MODULE LIFECYCLE --------------------

MOD_TEST() {
    memset(&citywhois_config, 0, sizeof(citywhois_config));
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, citywhois_configtest);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, citywhois_configposttest);
    return MOD_SUCCESS;
}

MOD_INIT() {
    MARK_AS_GLOBAL_MODULE(modinfo);
    HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, citywhois_configrun);
    HookAdd(modinfo->handle, HOOKTYPE_WHOIS, 0, citywhois_whois);
    return MOD_SUCCESS;
}

MOD_LOAD() {
    return MOD_SUCCESS;
}

MOD_UNLOAD() {
    if (citywhois_config.db_loaded) {
        MMDB_close(&citywhois_config.mmdb);
        citywhois_config.db_loaded = 0;
    }

    if (citywhois_config.db_path) {
        free(citywhois_config.db_path);
        citywhois_config.db_path = NULL;
    }

    return MOD_SUCCESS;
}

// -------------------- CONFIG --------------------

int citywhois_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
    int errors = 0;

    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || strcmp(ce->name, MYCONF))
        return 0;

    ConfigEntry *cep;
    for (cep = ce->items; cep; cep = cep->next) {
        if (!strcmp(cep->name, "db")) {
            char *db_path = strdup(cep->value);
            if (!db_path) {
                config_error("%s:%d: Out of memory",
                    cep->file->filename, cep->line_number);
                errors++;
                continue;
            }

            convert_to_absolute_path(&db_path, NULL);

            if (access(db_path, R_OK) != 0) {
                config_error("%s:%d: Cannot access DB file '%s': %s",
                    cep->file->filename, cep->line_number,
                    db_path, strerror(errno));
                free(db_path);
                errors++;
                continue;
            }

            // store temporarily ONLY
            if (tmp_db_path)
                free(tmp_db_path);
            tmp_db_path = db_path;
        } else {
            config_error("%s:%d: Unknown directive '%s' in %s block",
                cep->file->filename, cep->line_number,
                cep->name, MYCONF);
            errors++;
        }
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int citywhois_configposttest(int *errs) {
    int errors = 0;

    if (!tmp_db_path) {
        config_error("CityWhois: Missing 'db' directive in %s block", MYCONF);
        errors++;
    }

    *errs = errors;
    return errors ? -1 : 1;
}

int citywhois_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
    if (type != CONFIG_MAIN)
        return 0;

    if (!ce || strcmp(ce->name, MYCONF))
        return 0;

    // Cleanup old DB if reloading
    if (citywhois_config.db_loaded) {
        MMDB_close(&citywhois_config.mmdb);
        citywhois_config.db_loaded = 0;
    }

    if (citywhois_config.db_path) {
        free(citywhois_config.db_path);
        citywhois_config.db_path = NULL;
    }

    // Apply new config
    if (tmp_db_path) {
        citywhois_config.db_path = tmp_db_path;
        tmp_db_path = NULL;

        int status = MMDB_open(citywhois_config.db_path,
                               MMDB_MODE_MMAP,
                               &citywhois_config.mmdb);

        if (status != MMDB_SUCCESS) {
            config_error("CityWhois: Failed to open MaxMind DB '%s': %s",
                citywhois_config.db_path,
                MMDB_strerror(status));
            return -1;
        }

        citywhois_config.db_loaded = 1;
    }

    return 1;
}

// -------------------- WHOIS HOOK --------------------

int citywhois_whois(Client *requester, Client *acptr, NameValuePrioList **list) {
    if (!IsOper(requester))
        return 0;

    if (!IsUser(acptr))
        return 0;

    if (!citywhois_config.db_loaded)
        return 0;

    if (acptr->ip && *acptr->ip) {
        int gai_error = 0, mmdb_error = MMDB_SUCCESS;

        MMDB_lookup_result_s result =
            MMDB_lookup_string(&citywhois_config.mmdb,
                               acptr->ip,
                               &gai_error,
                               &mmdb_error);

        if (gai_error != 0 || mmdb_error != MMDB_SUCCESS)
            return 0;

        if (result.found_entry) {
            MMDB_entry_data_s city_data;

            int status = MMDB_get_value(&result.entry,
                                        &city_data,
                                        "city", "names", "en", NULL);

            if (status == MMDB_SUCCESS && city_data.has_data) {
                char city[256];
                snprintf(city, sizeof(city), "%.*s",
                    (int)city_data.data_size,
                    city_data.utf8_string);

                add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                    "%s :is connecting from City: %s",
                    acptr->name, city);
            } else {
                add_nvplist_numeric_fmt(list, 320, "city", acptr, 320,
                    "%s :City unknown", acptr->name);
            }
        }
    }

    return 0;
}
