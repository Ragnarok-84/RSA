#include <vector>
#include <algorithm>
using namespace std;
class Solution
{
public:
    int maxProfit(vector<int> &prices)
    {
        int l = 0, r = 1;
        int maxProfit = 0;

        while (r < prices.size())
        {
            if (prices[r] > prices[l])
            {
                maxProfit = max(maxProfit, prices[r] - prices[l]);
            }
            else
            {
                l = r; // tìm giá mua rẻ hơn
            }
            r++;
        }
        return maxProfit;
    }
};
