// agentxd_main.cpp — entry point for smartmon-snmp-agentxd

#include "agentxd_cache.h"
#include "agentxd_config.h"
#include "agentxd_datasrc.h"
#include "agentxd_loop.h"
#include "agentxd_state_db.h"
#include "agentxd_systemd.h"
#include "version.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include <systemd/sd-daemon.h>

#ifndef AGENTXD_SYSCONFDIR
#define AGENTXD_SYSCONFDIR "/etc/smartmontools"
#endif

static const char *default_config_path =
    AGENTXD_SYSCONFDIR "/snmp-agentxd.conf";

static volatile sig_atomic_t g_exit_signal = 0;
static volatile sig_atomic_t g_reload_signal = 0;

static void handle_sigterm(int) { g_exit_signal = 1; }
static void handle_sighup(int)  { g_reload_signal = 1; }

static void install_signals()
{
    struct sigaction sa{};
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = handle_sigterm;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);

    sa.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa, nullptr);

    // Ignore SIGPIPE — net-snmp may write to a closed AgentX socket
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr);
}

static void daemonise()
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(EXIT_FAILURE); }
    if (pid > 0) exit(EXIT_SUCCESS);   // parent exits

    if (setsid() < 0) { perror("setsid"); exit(EXIT_FAILURE); }

    // Second fork prevents re-acquiring a controlling terminal
    pid = fork();
    if (pid < 0) { perror("fork"); exit(EXIT_FAILURE); }
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") != 0) { perror("chdir"); exit(EXIT_FAILURE); }

    // Close and redirect standard fds
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -c FILE   Config file (default: %s)\n"
        "  -f        Run in foreground (do not daemonise)\n"
        "  -v        Verbose: log scan flow and device load summaries\n"
        "  -vv       Very verbose: add per-sensor detail and SNMP iterator calls\n"
        "  -V        Print version and exit\n"
        "  -h        Show this help\n",
        prog, default_config_path);
}

int main(int argc, char *argv[])
{
    const char *config_path = default_config_path;
    bool foreground = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:fhvV")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'f': foreground = true;    break;
        case 'v': ++g_verbosity;        break;
        case 'V': printf("smartmon-snmp-agentxd " AGENTXD_VERSION "\n"); return EXIT_SUCCESS;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        default:  usage(argv[0]); return EXIT_FAILURE;
        }
    }

    // Mirror syslog() to stderr for interactive foreground debugging only.
    // Under systemd the service also runs with -f, but journald captures both
    // syslog and stderr, so LOG_PERROR would duplicate every log line.
    int log_opts = LOG_PID | LOG_CONS;
    if (foreground && isatty(STDERR_FILENO))
        log_opts |= LOG_PERROR;
    openlog("smartmon-snmp-agentxd", log_opts, LOG_DAEMON);

    AgentxConfig cfg;
    cfg.foreground = foreground;

    sd_notify(0, "STATUS=v" AGENTXD_VERSION " starting up...");

    if (!agentxd_config_load(config_path, cfg)) {
        syslog(LOG_ERR, "Configuration error — exiting.");
        return EXIT_FAILURE;
    }
    g_poll_failure_threshold  = cfg.poll_failure_threshold;
    g_test_mode               = cfg.test_mode;
    g_sensor_resend_interval  = cfg.sensor_resend_interval;
    g_sensor_hysteresis       = cfg.sensor_hysteresis;

    if (!foreground)
        daemonise();

    install_signals();

    syslog(LOG_INFO, "Starting smartmon-snmp-agentxd, state_dir='%s', "
           "agentx_socket='%s', cache_timeout=%us",
           cfg.state_dir.c_str(), cfg.agentx_socket.c_str(), cfg.cache_timeout);

    sd_notify(0, "STATUS=v" AGENTXD_VERSION " config loaded, loading device data...");

    // Open and restore persisted table-change timestamps (optional)
    state_db_open(cfg.state_db_path);
    state_db_load();

    // Validate smartd configuration and set up inotify watcher
    if (!agentxd_datasrc_init(cfg.state_dir)) {
        syslog(LOG_ERR, "Data source initialisation failed — exiting.");
        state_db_close();
        return EXIT_FAILURE;
    }

    sd_notify(0, "STATUS=v" AGENTXD_VERSION " connecting to SNMP master...");

    // Initialise AgentX connection and register MIB tables
    if (!agentxd_loop_init(cfg)) {
        syslog(LOG_ERR, "AgentX initialisation failed — exiting.");
        agentxd_datasrc_shutdown();
        state_db_close();
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "AgentX registered, entering main loop.");

    sd_notify(0, "READY=1");
    agentxd_sd_notify_status();

    // Main select loop — runs until SIGTERM/SIGINT
    bool clean_exit = agentxd_loop_run(&g_exit_signal, &g_reload_signal, cfg);

    sd_notify(0, "STOPPING=1\nSTATUS=v" AGENTXD_VERSION " shutting down");
    syslog(LOG_INFO, "Shutting down.");
    agentxd_loop_shutdown();
    agentxd_datasrc_shutdown();
    state_db_close();
    closelog();
    return clean_exit ? EXIT_SUCCESS : EXIT_FAILURE;
}
