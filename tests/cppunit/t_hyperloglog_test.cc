#include <gtest/gtest.h>

#include <string>

#include "test_base.h"
#include "types/redis_hyperloglog.h"

using namespace std;

class RedisHyperloglogTest : public TestBase {
 protected:
  explicit RedisHyperloglogTest() : TestBase() { hll = std::make_unique<Redis::HyperLogLog>(storage_, "hll_ns"); }
  ~RedisHyperloglogTest() = default;
  void SetUp() override {}

 protected:
  std::unique_ptr<Redis::HyperLogLog> hll;
};

TEST_F(RedisHyperloglogTest, PFAddAndCountBase) {
  const string key = "hll_1111";

  hll->Del(key);

  map<string, int> member_2_count{
      {"member1", 1}, {"member2", 2}, {"member3", 3}, {"member4", 4}, {"member4", 4}, {"member4", 4},
  };
  for (auto &item : member_2_count) {
    auto s = hll->PFAdd(key, item.first);
    ASSERT_TRUE(s.ok());
    int count = hll->PFCount(key);
    ASSERT_EQ(count, item.second);
  }
}

TEST_F(RedisHyperloglogTest, PFMerge) {
  const string key = "hll_1111";
  const string key2 = "hll_2222";
  const string key3 = "hll_3333";

  hll->Del(key2);
  hll->Del(key);
  hll->Del(key3);

  map<string, int> member_2_count{
      {"member1", 1}, {"member2", 2}, {"member3", 3}, {"member4", 4}, {"member4", 4}, {"member4", 4},
  };

  map<string, int> member_2_count2{
      {"new_member1", 1}, {"new_member2", 2}, {"new_member3", 3},
      {"new_member4", 4}, {"new_member4", 4}, {"new_member4", 4},
  };
  for (auto &item : member_2_count2) {
    auto s = hll->PFAdd(key3, item.first);
    ASSERT_TRUE(s.ok());
  }
  for (auto &item : member_2_count) {
    auto s = hll->PFAdd(key, item.first);
    ASSERT_TRUE(s.ok());
    s = hll->PFAdd(key2, item.first);
    ASSERT_TRUE(s.ok());
    int count = hll->PFCount(key);
    ASSERT_EQ(count, item.second);
    count = hll->PFCount(key2);
    ASSERT_EQ(count, item.second);
  }

  hll->PFMerge({key, key2});
  auto after_merge = hll->PFCount(key);
  ASSERT_EQ(after_merge, 4);

  hll->PFMerge({key, key2, key3});
  after_merge = hll->PFCount(key);
  ASSERT_EQ(after_merge, 8);
}