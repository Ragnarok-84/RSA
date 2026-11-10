#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    bool isPalindrome(string s)
    {
        string t = "";
        for (char c : s)
        {
            if (isalnum(c))
            {
                t += c;
            }
        }
        transform(t.begin(), t.end(), t.begin(), ::tolower);
        int n = t.length();
        s = "";
        for (int i = n - 1; i >= 0; i--)
        {
            s += t[i];
        }
        return t == s;
    }
};
