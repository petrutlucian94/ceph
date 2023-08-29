/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2023 Cloudbase Solutions
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "rados_client_cache.h"

#include "common/errno.h"

std::shared_ptr<librados::Rados> RadosClientCache::init_client(
  std::string& client_name, std::string& cluster_name)
{
  auto rados = std::make_shared<librados::Rados>();

  int r = rados->init2(client_name.c_str(), cluster_name.c_str(), 0);
  if (r < 0) {
    derr << "couldn't initialize rados: " << cpp_strerror(r)
         << dendl;
    return std::shared_ptr<librados::Rados>();
  }

  r = rados->conf_read_file(nullptr);
  if (r < 0) {
    derr << "couldn't ead conf file: " << cpp_strerror(r)
         << dendl;
    return std::shared_ptr<librados::Rados>();
  }

  r = rados->connect();
  if (r < 0) {
    derr << "couldn't establish rados connection: "
         << cpp_strerror(r) << dendl;
    return std::shared_ptr<librados::Rados>();
  } else {
    dout(1) << "successfully initialized rados connection" << dendl;
  }

  return rados;
}

std::shared_ptr<librados::Rados> RadosClientCache::get_client(
  std::string& client_name, std::string& cluster_name)
{
  std::unique_lock l{cache_lock};

  std::string key = client_name + "@" + cluster_name;
  auto cached_client = cache.find(key);
  if (cached_client != cache.end()) {
    dout(5) << "reusing cached rados client: " << key << dendl;
    return cached_client->second;
  }

  dout(5) << "creating new rados client: " << key << dendl;
  auto client = init_client(client_name, cluster_name);
  cache.insert(std::pair{key, client});
  return client;
}
