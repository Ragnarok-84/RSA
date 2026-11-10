#include <string>
#include <set>
#include <algorithm>
using namespace std;
class Solution
{
public:
    int lengthOfLongestSubstring(string s)
    {
        int n = s.size();
        int l = 0;
        int maxLen = 0;
        set<char> c;

        for (int r = 0; r < n; r++)
        {
            while (c.count(s[r]))
            {
                c.erase(s[l]);
                l++;
            }
            c.insert(s[r]);
            maxLen = max(maxLen, r - l + 1);
        }
        return maxLen;
    }
};
