package com.nadhem.produits;



import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;

import com.nadhem.produits.entities.Produit;
import com.nadhem.produits.repos.ProduitRepository;
import com.nadhem.produits.service.ProduitService;


@SpringBootTest
class ProduitsApplicationTests {

	@Autowired
	private ProduitRepository produitRepository;
	
	@Autowired
	private ProduitService produitService;
	
	@Test
	public void testCreateProduit() {
	Produit prod = new Produit("PC Asus",1500.500,new Date());
	produitRepository.save(prod);
	}
	
	@Test
	public void testFindProduit()
	{
	Produit p = produitRepository.findById(1L).get();
	System.out.println(p);
	}
	
	@Test
	public void testUpdateProduit()
	{
	Produit p = produitRepository.findById(1L).get();
	p.setPrixProduit(2000.0);
	produitRepository.save(p);
	
	System.out.println(p);
	}
	
	@Test
	public void testDeleteProduit()
	{
		produitRepository.deleteById(1L);
	}
	
	@Test
	public void testFindAllProduits()
	{
		List<Produit> prods = produitRepository.findAll();
		
		for (Produit p:prods)
			 System.out.println(p);
		
	}
	
	
	@Test
	public void testFindProduitByNom()
	{
	List<Produit> prods = produitRepository.findByNomProduit("PS 4");
	
	for (Produit p:prods)
		 System.out.println(p);
	
	}
	
	@Test
	public void testFindProduitByNomContains()
	{
	List<Produit> prods = produitRepository.findByNomProduitContains("P");
	
	for (Produit p:prods)
		 System.out.println(p);
	
	}
	
	@Test
	public void testfindByNomPrix()
	{
	List<Produit> prods = produitRepository.findByNomPrix("PS 4", 1000.0);
		for (Produit p : prods)
			{
				System.out.println(p);
			}
	}
	
	
	
	
	
	@Test
	public void testfindByOrderByNomProduitAsc()
	{
	List<Produit> prods =  produitRepository.findByOrderByNomProduitAsc();
	for (Produit p : prods)
		{
			System.out.println(p);
		}
	}
	
	@Test
	public void testTrierProduitsNomsPrix()
	{
	List<Produit> prods = produitRepository.trierProduitsNomsPrix();
	for (Produit p : prods)
	{
	System.out.println(p);
	}
	}
	
	@Test
	public void testFindByNomProduitContains()
	{
	Page<Produit> prods = produitService.getAllProduitsParPage(0,2);
	System.out.println(prods.getSize());
	System.out.println(prods.getTotalElements());
	System.out.println(prods.getTotalPages());
	
	prods.getContent().forEach(p -> {System.out.println(p.toString());
	});
	/*ou bien
	for (Produit p : prods.getContent())
	{
	System.out.println(p);
	} */
	}
	
	
}
