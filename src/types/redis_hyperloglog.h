/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#pragma once

#include "common/range_spec.h"
#include "storage/redis_db.h"
#include "storage/redis_metadata.h"
#include "types/redis_string.h"

namespace Redis {

class HyperLogLog : public Database {
 public:
  HyperLogLog(Engine::Storage *storage, const std::string &ns) : Database(storage, ns) {}
  rocksdb::Status PFAdd(const Slice &user_key, const Slice &member);
  int PFCount(const Slice &user_key);
  rocksdb::Status PFMerge(const std::vector<Slice> &pairs);

 private:
  rocksdb::Status getValue(const std::string &user_keys, std::string *raw_value);
  std::vector<rocksdb::Status> getValues(const std::vector<Slice> &ns_keys, std::vector<std::string> *values);
  // HyperLogLog sparse representation bytes limit. The limit includes the
  // 16 bytes header. When an HyperLogLog using the sparse representation crosses
  // this limit, it is convereted into the dense representation.
  // A value greater than 16000 is totally useless, since at that point the
  // dense representation is more memory efficient.
  //
  // The suggested value is ~ 3000 in order to have the benefits of
  // the space efficient encoding without slowing down too much PFADD,
  // which is O(N) with the sparse encoding. Thev value can be raised to
  // ~ 10000 when CPU is not a concern, but space is, and the data set is
  // composed of many HyperLogLogs with cardinality in the 0 - 15000 range.
  uint32_t hll_sparse_max_bytes = 3000;
};
}  // namespace Redis
