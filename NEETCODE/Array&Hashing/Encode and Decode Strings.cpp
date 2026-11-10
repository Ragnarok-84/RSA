#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    string encode(vector<string> &strs)
    {
        string s = "";
        for (auto str : strs)
        {
            s += str + ">";
        }
        return s;
    }

    vector<string> decode(string s)
    {
        vector<string> re;
        string t = "";
        for (char c : s)
        {
            if (c == '>')
            {
                re.push_back(t);
                t = "";
            }
            else
            {
                t += c;
            }
        }
        return re;
    }
};
