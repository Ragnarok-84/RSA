#include <bits/stdc++.h>
using namespace std;
class Solution
{
public:
    int carFleet(int target, vector<int> &position, vector<int> &speed)
    {
        int n = speed.size();
        vector<pair<double, int>> time_pos;
        for (int i = 0; i < n; i++)
        {
            double t = 1.0 * (target - position[i]) / speed[i];
            time_pos.push_back({t, position[i]});
        }
        sort(time_pos.begin(), time_pos.end(), [](auto &a, auto &b)
             {
            if(a.second != b.second){
                return a.second > b.second;
            }
            else{
                return a.first < b.first;
            } });
        double maxTime = time_pos[0].first;
        int count = 1;
        for (int i = 1; i < n; i++)
        {
            if (time_pos[i].first > maxTime)
            {
                count++;
                maxTime = time_pos[i].first;
            }
        }
        return count;
    }
};
