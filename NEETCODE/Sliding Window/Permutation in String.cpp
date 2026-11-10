#include <string>
#include <algorithm>
using namespace std;
class Solution
{
public:
    string change(string t)
    {
        sort(t.begin(), t.end());
        return t;
    }
    bool checkInclusion(string s1, string s2)
    {
        s1 = change(s1);
        int n = s1.length(), m = s2.length();
        if (n > m)
        {
            return false;
        }
        int l = 0;
        while (l <= m - n)
        {
            string s = s2.substr(l, n);
            if (s1 == change(s))
            {
                return true;
            }
            l++;
        }
        return false;
    }
};
