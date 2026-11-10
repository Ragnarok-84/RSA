#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    vector<int> twoSum(vector<int> &nums, int target)
    {
        vector<int> s;
        int n = nums.size();
        vector<pair<int, int>> a;
        for (int i = 0; i < n; i++)
        {
            a.push_back({nums[i], i});
        }
        sort(a.begin(), a.end());
        int i = 0, j = n - 1;
        while (i < j)
        {
            int k = a[i].first + a[j].first;
            if (k < target)
            {
                i++;
            }
            else if (k == target)
            {
                if (a[i].second > a[j].second)
                {
                    s.push_back(a[j].second);
                    s.push_back(a[i].second);
                }
                else
                {
                    s.push_back(a[i].second);
                    s.push_back(a[j].second);
                }
                i++;
                j--;
            }
            else
            {
                j--;
            }
        }
        return s;
    }
};