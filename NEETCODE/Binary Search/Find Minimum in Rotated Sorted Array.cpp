#include <vector>
using namespace std;
class Solution
{
public:
    int findMin(vector<int> &nums)
    {
        int l = 0, r = nums.size() - 1;
        while (l < r)
        {
            int mid = l + (r - l) / 2;
            if (nums[mid] > nums[r])
            {
                l = mid + 1; // Min nằm bên phải mid
            }
            else
            {
                r = mid; // Min nằm bên trái hoặc chính mid
            }
        }
        return nums[l];
    }
};
