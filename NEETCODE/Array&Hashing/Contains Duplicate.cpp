#include <bits/stdc++.h>
using namespace std;

class Solution
{
public:
    bool hasDuplicate(vector<int> &nums)
    {
        set<int> numss;
        for (int num : nums)
        {
            numss.insert(num);
        }
        if (numss.size() < nums.size())
        {
            return true;
        }
        else
        {
            return false;
        }
    }
};