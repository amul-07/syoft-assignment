import { Router } from 'express';
import { getProducts, getProduct, addProducts, updateProduct, removeProduct } from '../controllers/products.js';
import { protect, restrictTo } from '../controllers/authentication.js';

const productRouter = Router();

productRouter.get('/:id', protect, restrictTo('Admin', 'Manager'), getProduct);
productRouter.get('', protect, restrictTo('Admin', 'Manager'), getProducts);
productRouter.post('/', protect, restrictTo('Admin'), addProducts);
productRouter.patch('/:id', protect, restrictTo('Admin', 'Manager'), updateProduct);
productRouter.delete('/:id', protect, restrictTo('Admin'), removeProduct);

export default productRouter;
