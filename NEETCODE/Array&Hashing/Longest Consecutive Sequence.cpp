#include <vector>
#include <set>
using namespace std;
class Solution
{
public:
    int longestConsecutive(vector<int> &nums)
    {
        if (nums.size() == 0)
        {
            return 0;
        }
        set<int> s;
        for (int i : nums)
        {
            s.insert(i);
        }
        vector<int> a;
        for (int i : s)
        {
            a.push_back(i);
        }
        int n = a.size();
        int count = 1, countmax = 1, last = 0;
        for (int i = 1; i < n; i++)
        {
            if (a[i] == a[last] + 1)
            {
                count++;
            }
            else
            {
                countmax = max(count, countmax);
                count = 1;
            }
            last++;
        }
        return max(count, countmax);
    }
};
