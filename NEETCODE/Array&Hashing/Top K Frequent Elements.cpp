#include <vector>
#include <map>
#include <algorithm>
using namespace std;
class Solution
{
public:
    vector<int> topKFrequent(vector<int> &nums, int k)
    {
        map<int, int> mp;
        for (int num : nums)
        {
            mp[num]++;
        }
        vector<pair<int, int>> v;
        for (auto &it : mp)
        {
            v.push_back({it.second, it.first});
        }
        sort(v.begin(), v.end(), greater<pair<int, int>>());
        vector<int> re;
        int i = 0;
        while (k > 0)
        {
            re.push_back(v[i].second);
            i++;
            k--;
        }
        return re;
    }
};
