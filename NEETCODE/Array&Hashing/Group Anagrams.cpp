#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    string change(string s)
    {
        sort(s.begin(), s.end());
        return s;
    }

    vector<vector<string>> groupAnagrams(vector<string> &strs)
    {
        map<string, vector<string>> m;

        for (string s : strs)
        {
            string t = change(s);
            m[t].push_back(s);
        }

        vector<vector<string>> res;
        for (auto &it : m)
        {
            res.push_back(it.second);
        }
        return res;
    }
};
