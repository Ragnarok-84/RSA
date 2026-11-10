#include <bits/stdc++.h>
using namespace std;

class Solution
{
public:
    string change(string s)
    {
        vector<char> a;
        for (char c : s)
        {
            a.push_back(c);
        }
        sort(a.begin(), a.end());
        string t = "";
        for (auto c : a)
        {
            t += c;
        }
        return t;
    }
    bool isAnagram(string s, string t)
    {
        string s1 = change(s), t1 = change(t);
        return s1 == t1;
    }
};
