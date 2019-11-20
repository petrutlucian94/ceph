#include "global/signal_handler.h"

void install_sighandler(int signum, signal_handler_t handler, int flags) {}
void sighup_handler(int signum) {}

// Install the standard Ceph signal handlers
void install_standard_sighandlers(void){}

/// initialize async signal handler framework
void init_async_signal_handler(){}

/// shutdown async signal handler framework
void shutdown_async_signal_handler(){}

/// queue an async signal
void queue_async_signal(int signum){}

/// install a safe, async, callback for the given signal
void register_async_signal_handler(int signum, signal_handler_t handler){}
void register_async_signal_handler_oneshot(int signum, signal_handler_t handler){}

/// uninstall a safe async signal callback
void unregister_async_signal_handler(int signum, signal_handler_t handler){}
