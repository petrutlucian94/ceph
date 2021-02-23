#define CEPH_DOKAN_IO_DEFAULT_TIMEOUT 60 * 5 // Seconds
#define CEPH_DOKAN_DEFAULT_THREAD_COUNT 10

// BOOL g_UseStdErr;
// BOOL g_DebugMode;

// int g_UID = 0;
// int g_GID = 0;
// BOOL g_UseACL = TRUE;

struct Config {
  bool removable = false;
  bool readonly = false;
  bool use_win_mount_mgr = false;
  bool current_session_only = false;
  bool dokan_debug = false;
  bool dokan_stderr = false;

  int uid = 0;
  int gid = 0;
  bool use_acl = true;
  int operation_timeout = CEPH_DOKAN_IO_DEFAULT_TIMEOUT;
  int thread_count = CEPH_DOKAN_DEFAULT_THREAD_COUNT;

  // TODO: check unicode support
  std::string mountpoint = "";
  std::string mount_subdir = "";
};

// TODO: list and unmap commands.
enum class Command {
  None,
  Version,
  Help,
  Map,
};
