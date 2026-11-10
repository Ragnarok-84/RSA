#include <vector>
#include <algorithm>
using namespace std;
class Solution
{
public:
    bool canEat(vector<int> &piles, int h, int k)
    {
        long long hours = 0;
        for (int pile : piles)
        {
            hours += (pile + k - 1) / k; // ceil(pile / k)
            if (hours > h)
                return false;
        }
        return true;
    }

    int minEatingSpeed(vector<int> &piles, int h)
    {
        int left = 1;
        int right = *max_element(piles.begin(), piles.end());
        int ans = right;

        while (left <= right)
        {
            int mid = left + (right - left) / 2; // Giống (left+right)/2 nhưng tránh tràn số
            if (canEat(piles, h, mid))
            {
                ans = mid;
                right = mid - 1;
            }
            else
            {
                left = mid + 1;
            }
        }
        return ans;
    }
};
