#include "common/errno.h"
#include "acconfig.h"

#include <sstream>
#include <string.h>

std::string cpp_strerror(int err)
{
  char buf[128];
  char *errmsg;

  if (err < 0)
    err = -err;
  std::ostringstream oss;
  buf[0] = '\0';

  // strerror_r returns char * on Linux, and does not always fill buf
#ifdef STRERROR_R_CHAR_P
  errmsg = strerror_r(err, buf, sizeof(buf));
#elif _WIN32
  strerror_s(buf, sizeof(buf), err);
  errmsg = buf;
#else
  strerror_r(err, buf, sizeof(buf));
  errmsg = buf;
#endif

  oss << "(" << err << ") " << errmsg;

  return oss.str();
}
