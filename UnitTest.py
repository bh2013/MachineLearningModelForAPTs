import unittest
import ReadData as ReadData



def test_readData():
    # Test readData function
    data = ReadData.readData()
    assert data.shape[0] == 1000
    


if __name__ == '__main__':
    unittest.main()